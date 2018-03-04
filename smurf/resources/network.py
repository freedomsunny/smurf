# encoding=utf-8
import json
import logging

from flask import jsonify
from flask_restful import marshal
from sqlalchemy import and_
import socket, struct
from IPy import IP
import copy
import json
from threading import Thread

import smurf.config as config
from .common import NETWORK_FIELDS
from smurf.api_requests.api_requests import post_http, delete_http, get_http
from smurf.db.models import db_session, Network, VlanIpAddress
import smurf.auth as auth
from smurf.utils import exec_cmd, get_token
from smurf.db.openstack_db import NetworkSegments
from smurf.api_requests.switch_config import SwitchConfig
from smurf.api_requests.sdn_switch_config import PyjsonrpcClient

logger = logging.getLogger(__name__)


class NetworkListAPI(auth.X_resource):
    """
    this is Network list plugins
    """

    def get(self):
        """
        method to get Network by user id
        """
        if not self.result.get("success"):
            return self.result
        user_id = self.context.get('user_id')
        networks = Network.query.filter(Network.removed == None).all()
        if not networks:
            em = "no networks"
            return {"error": [{"code": 401, "msg": "{0}".format(em)}]}
        allowed_networks = [network for network in networks if network.user_id == user_id]

        return {"networks": [marshal(network, NETWORK_FIELDS) for network in allowed_networks]}

    def post(self):
        """
        method to sync Network from OpenStack's user define network
        """
        if not self.result.get("success"):
            return self.result
        try:
            # description = self.args.get("description")
            user_id = self.context.get('user_id')

            # get user's all networks from OpenStack
            openstack_networks = get_user_networks(self.token)
            if not openstack_networks:
                return False, 500
            # get user's all network from docker(smurf)
            docker_networks = Network.query.filter(Network.user_id == user_id).all()
            if not docker_networks:
                invalid_nets = []
            else:
                invalid_nets = copy.copy(docker_networks)
            for openstack_network in openstack_networks:
                network_id = openstack_network
                subnet_ids = openstack_networks.get(network_id).get("sub_nets")
                status = openstack_networks.get(network_id).get("status")
                # get network's vni
                networksegment = NetworkSegments.query.filter(NetworkSegments.network_id == network_id).first()
                if networksegment is None:
                    em = "could not be find network's vni id from openstack. network id: {0}".format(network_id)
                    logger.info(em)
                    return False, 500
                vni = networksegment.segmentation_id
                # if network has no Vxlan id. the container can not use that network
                if not vni:
                    continue
                # generate uniqueness vlan id
                networks = Network.query.filter(Network.vlan != None).all()
                vlan_id = set(range(config.vlan_range[0], config.vlan_range[1])).difference(
                    set([network.vlan for network in networks])).pop()
                if not vlan_id:
                    em = 'no available vlan id allocation'
                    logger.warn(em)
                    return False, 500
                for subnet_id in subnet_ids:
                    ret = [s for s in docker_networks if s.network_id == network_id and s.subnet_id == subnet_id]
                    # if not found network in docker platform. add the network in docker platform
                    data = get_subnet(self.token, subnet_id)
                    if not data:
                        return False, 500
                    cidr = data.get('subnet').get('cidr')
                    gateway = data.get('subnet').get('gateway_ip')
                    name = data.get('subnet').get("name")
                    if not ret:
                        # get openstack network's info
                        # get subnet cidr and gateway
                        network = Network(name=name, description=None, user_id=user_id, vlan=vlan_id, vni=vni,
                                          network_id=network_id, subnet_id=subnet_id, cidr=cidr, gateway=gateway,
                                          status=status)
                        db_session.add(network)
                        db_session.flush()
                    else:
                        Network.query.filter(and_(Network.network_id == network_id,
                                                  Network.subnet_id == subnet_id)).update({Network.name: name,
                                                                                           Network.status: status,
                                                                                           Network.cidr: cidr,
                                                                                           Network.gateway: gateway})
                        # db_session.flush()
                        db_session.commit()
                    # if found network in docker platform. update network info
                    # exclude OpenStack's networks from docker db. it is invalid networks
                    invalid_nets = [s for s in invalid_nets if s.subnet_id != subnet_id and s.network_id != network_id]

            # delete invalid nets
            for invalid_net in invalid_nets:
                # remove network if is created on docker
                if invalid_net.iscreated:
                    # subnet id is the docker network name
                    net_name = invalid_net.subnet_id
                    VlanNetworkManager.delete_network(net_name)
                Network.query.filter(and_(Network.network_id == invalid_net.network_id,
                                          Network.subnet_id == invalid_net.subnet_id)).delete()
                db_session.flush()

            db_session.commit()
            return True, 200
        except Exception as e:
            db_session.rollback()
            em = "cannot sync network from OpenStack. msg: {0}".format(e)
            logger.warn(em)
            return False, 500

    def delete(self, name):
        """
        method to delete a Network
        """
        if not self.result.get("success"):
            return self.result

        user_id = self.context.get('user_id')
        exist_network = Network.query.filter(and_(Network.name == name, Network.removed == None)).first()
        if not exist_network:
            em = 'Network {0} is not exist'.format(name)
            logger.info(em)
            return {"error": [{"code": 401, "msg": "{0}".format(em)}]}
        network = Network.query.filter(
            and_(Network.user_id == user_id, Network.name == name)).first()
        try:
            # when delete a network we must recycling ports from openstack
            VlanIpaddress = VlanIpAddress.query.filter(VlanIpAddress.network_id == network.id).all()
            # recycling ports from openstack
            if VlanIpaddress:
                for VlanIpaddres in VlanIpaddress:
                    ret = delete_port(self.token, VlanIpaddres.port_id)
                    if ret.get("error"):
                        return ret
                    db_session.delete(VlanIpaddres)
                    db_session.flush()
            db_session.delete(network)
            db_session.commit()
            return {"success": [{"code": 200, "msg": ""}]}
        except Exception as e:
            em = "Unable to delete network: {0}".format(e)
            logger.warn(em)
            return {"error": [{"code": 500, "msg": "{0}".format(em)}]}

    def put(self):
        """
        update a network
        """
        if not self.result.get("success"):
            return self.result

        name = self.args.get('name')
        user_id = self.context.get('user_id')
        n_name = self.args.get('n_name')
        description = self.args.get('description')
        data = {}
        if n_name:
            data.update({'name': n_name})
        if description:
            data.update({'description': description})

        exist_network = Network.query.filter(and_(Network.name == name,
                                                  Network.removed == None,
                                                  Network.user_id == user_id)).first()
        if not exist_network:
            em = 'Network {0} is not exist'.format(name)
            logger.info(em)
            return {"error": [{"code": 401, "msg": "{0}".format(em)}]}
        try:
            Network.query.filter(and_(Network.user_id == user_id,
                                      Network.name == name)).update(data)
            db_session.commit()
            return {'ec': 0, 'em': 'success'}
        except Exception as e:
            db_session.rollback()
            logger.warn('Unable to update networke, user id=`%s` name=`%s`' % (user_id, name))
            return {"error": [{"code": 500, "msg": "{0}".format(e)}]}


def GetPortAbout(network_id, subnet_id, mac_address, tenant_id):
    """
    method to get network's ip address from openstack 
    :param token: 
    :param network_id: 
    :param subnet_id: 
    :return: 
    """
    # get the admin token
    token = get_token()
    if not token:
        em = "get admin token error......"
        logger.warn(em)
    if not config.controler_host or not config.neutron_api_port:
        em = "keystone_host or neutron_api_port is not configured"
        logger.warn(em)
        return {"error": [{"code": 500, "msg": "{0}".format(em)}]}
    url = 'http://{0}:{1}/v2.0/ports'.format(config.controler_host, config.neutron_api_port)

    if not network_id or not subnet_id:
        em = "invalid parameter network_id or subnet_id"
        logger.warn(em)
        return {"error": [{"code": 500, "msg": "{0}".format(em)}]}

    bind_host = config.overlay_ip.replace(".", "-")
    # data = {"port": {"network_id": network_id,
    #                  "fixed_ips": [{"subnet_id": subnet_id}],
    #                  "mac_address": mac_address, "device_owner": "neutron:LOADBALANCERV2"}}

    data = {"port": {"network_id": network_id,
                     "tenant_id": tenant_id,
                     "fixed_ips": [{"subnet_id": subnet_id,
                                    }
                                   ],
                     "mac_address": mac_address,
                     "binding:host_id": bind_host,
                     "device_owner": "compute:nova"
                     }
            }
    data = json.dumps(data)

    header = {'Content-type': 'application/json', 'X-Auth-Token': token.strip()}
    ret = post_http(url=url, data=data, headers=header)
    # check is it error
    if ret.status_code != 201:
        em = "openstack error.assign ip address from openstack error"
        logger.warn(em)
        return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
    return ret.json()


def delete_port(token, port_id):
    if not token or not port_id:
        em = "token or port_id is invalid"
        return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
    header = {'X-Auth-Token': token.strip()}
    url = "http://{0}:{1}/v2.0/ports/{2}".format(config.controler_host,
                                                 config.neutron_api_port,
                                                 port_id.strip())
    ret = delete_http(url=url, headers=header)
    # check is it error
    if ret.status_code != 204:
        em = "error delete port with id :{0}. code: <{1}>".format(port_id, ret.status_code)
        return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
    return {"success": [{"code": 200, "msg": ""}]}


def get_subnet(token, subnet_id):
    """
    method to get subnet info from openstack
    :param token: 
    :param subnet_id: 
    :return: 
    """
    if not token or not subnet_id:
        em = "token or subnet_id is invalid"
        return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
    header = {'X-Auth-Token': token.strip()}
    url = "http://{0}:{1}/v2.0/subnets/{2}".format(config.controler_host,
                                                   config.neutron_api_port,
                                                   subnet_id)
    ret = get_http(url=url, headers=header)
    # check is it error
    if ret.status_code != 200:
        return {}
    return ret.json()


class VlanNetworkManager(object):
    """
    docker network Manager
    """
    cmd_prefix = ["docker network"]

    @staticmethod
    def create_network(cidr, vlanID, name, gateway=None):
        """
        method to add a vlan network
        :return: 
        """
        ip, mask = cidr.split('/')
        net_obj = IpExpr(ip, int(mask))
        start, end = net_obj.net_start, net_obj.net_end

        args = ["create",
                "-d vlcp",
                "--ipam-driver vlcp",
                "--subnet {0}".format(cidr),
                "-o physicalnetwork=vlan",
                "-o vlanid={0}".format(vlanID),
                "-o subnet:allocated_start={0}".format(start),
                "-o subnet:allocated_end={0}".format(end),
                "{0}".format(name)
                ]
        if gateway:
            gw_list = "--gateway {0}".format(gateway)
            args.insert(4, gw_list)
        full_args = VlanNetworkManager.cmd_prefix + args
        ret = exec_cmd(full_args)
        return ret

    @staticmethod
    def delete_network(name):
        """
        method to delete a vlan network
        :return: 
        """
        args = ["rm",
                "{0}".format(name)
                ]
        full_args = VlanNetworkManager.cmd_prefix + args
        ret = exec_cmd(full_args)
        return ret


def get_user_networks(token):
    """get user's all network from OpenStack"""
    if not token:
        em = "invalid token"
        logger.info(em)
    networks = {}
    headers = {'X-Auth-Token': token.strip()}
    ret = get_http(url=config.network_ep, headers=headers)
    if ret.status_code != 200:
        em = "get network error....."
        logger.warn(em)
        return {}
    for network in ret.json()["networks"]:
        mtu = network.get("mtu")
        if mtu and mtu == 1450:
            net_id = network.get("id")
            net_name = network.get("name")
            sub_nets = network.get("subnets")
            status = network.get("status")
            networks[net_id] = {"name": net_name, "sub_nets": sub_nets, "status": status}
    return networks


class IpExpr(object):
    def __init__(self, ip, mask):
        self.ip = ip
        self.mask = mask
        self.network = self.get_network()
        self.broadcast = self.get_broadcast()
        self.net_int = self.get_net_int()
        self.dhcp_listen_addr = self.get_dhcp_listen_addr()
        self.available_ips = self.get_available_ips()
        self.gateway = self.get_gateway()
        self.net_start = self.get_start()
        self.net_end = self.get_end()

    def get_network(self):
        network = str(IP(self.ip).make_net(self.mask)).split('/')[0]
        return network

    def get_broadcast(self):
        broadcast = IP('{}/{}'.format(self.network, self.mask)).broadcast()
        return broadcast

    def get_net_int(self):
        net_int = socket.ntohl(struct.unpack("I", socket.inet_aton(self.network))[0])
        return net_int

    def get_dhcp_listen_addr(self):
        dhcp_listen_addr = socket.inet_ntoa(struct.pack('I', socket.htonl(self.net_int + 1)))
        return dhcp_listen_addr

    def get_available_ips(self):
        available_ips = 2 ** (32 - self.mask) - 2
        return available_ips

    def get_gateway(self):
        gateway = socket.inet_ntoa(struct.pack('I', socket.htonl(self.net_int + self.available_ips)))
        return gateway

    def get_start(self):
        """by default return network + 2(eg.192.168.0.0/24 return 192.168.0.2)"""
        start = socket.inet_ntoa(struct.pack('I', socket.htonl(self.net_int + 2)))
        return start

    def get_end(self):
        """by default return broadcast - 2(eg.192.168.0.0/24 return 192.168.0.253)"""
        end = socket.inet_ntoa(struct.pack('I', socket.htonl(self.net_int + self.available_ips - 1)))
        return end


class ConfigureSdnSwitch(auth.X_resource):
    def post(self):
        try:
            if not self.result.get("success"):
                return self.result
            network_id = self.args.get('network_id').strip()
            sw_ip = self.args.get('sw_ip').strip()
            sw_pwd = self.args.get('sw_pwd').strip()
            sw_user = self.args.get('sw_user').strip()
            network = Network.query.filter(Network.network_id == network_id).first()
            if not network:
                em = "can not fond network. id: <{0}>".format(network_id)
                logger.warn(em)
                return 400
            vlan = network.vlan
            vni = network.vni
            if not network.iscreated:
                task = Thread(target=lambda: ConfigureSdnSwitch.add_vtep(sw_ip, sw_user, sw_pwd, vlan, vni))
                task.setDaemon(True)
                task.start()
            return {"success": {"code": 200, "msg": ""}}
        except Exception as e:
            db_session.rollback()
            em = "config sdn switch error. msg: <{0}>".format(e)
            logger.warn(em)
            return 500

    def delete(self):
        try:
            if not self.result.get("success"):
                return self.result
            network_id = self.args.get('network_id')
            sw_ip = self.args.get('sw_ip')
            sw_pwd = self.args.get('sw_pwd')
            sw_user = self.args.get('sw_user')
            network = Network.query.filter(Network.network_id == network_id).first()
            if not network:
                em = "can not fond network. id: <{0}>".format(network_id)
                logger.warn(em)
                return 400
            vlan = network.vlan
            if network.iscreated:
                task = Thread(target=lambda: ConfigureSdnSwitch.delete_vtep(sw_ip, sw_user, sw_pwd, vlan, network_id))
                task.setDaemon(True)
                task.start()
            return {"success": {"code": 200, "msg": ""}}
        except Exception as e:
            em = "delete vtep error. msg: <{0}>".format(e)
            logger.warn(em)
            return 500

    @staticmethod
    def add_vtep(sw_ip, sw_user, sw_pwd, vlan, vni):
        try:
            sdn_switch_obj = PyjsonrpcClient(sw_ip, username=sw_user, password=sw_pwd)
            vteps = sdn_switch_obj.get_vteps()
            if vteps.get("error"):
                return vteps
            for vtep_index, vtep_ip in vteps.iteritems():
                sdn_switch_obj.add_vni_mapping(vlan, vni, vtep_index)
        except Exception as e:
            em = "config sdn switch error. msg: <{0}>".format(e)
            logger.warn(em)
            return 500

    @staticmethod
    def delete_vtep(sw_ip, sw_user, sw_pwd, vlan, network_id):
        try:
            sdn_switch_obj = PyjsonrpcClient(sw_ip, username=sw_user, password=sw_pwd)
            vteps = sdn_switch_obj.get_vteps()
            if vteps.get("error"):
                return vteps
            for vtep_index, vtep_ip in vteps.iteritems():
                sdn_switch_obj.delete_vni_mapping(vlan, vtep_index)
            Network.query.filter(Network.network_id == network_id).update({Network.iscreated: False})
            db_session.commit()
        except Exception as e:
            db_session.rollback()
            em = "delete vtep error. msg: <{0}>".format(e)
            logger.warn(em)
            return 500


class ConfigureL2Switch(auth.X_resource):
    def post(self):
        try:
            if not self.result.get("success"):
                return self.result
            network_id = self.args.get('network_id').strip()
            sw_ip = self.args.get('sw_ip').strip()
            sw_port = self.args.get('sw_port').strip()
            sw_pwd = self.args.get('sw_pwd').strip()
            sw_user = self.args.get('sw_user').strip()
            network = Network.query.filter(Network.network_id == network_id).first()
            if not network:
                em = "can not fond network. id: <{0}>".format(network_id)
                logger.warn(em)
                return 400
            vlan = network.vlan
            ConfigureL2Switch.set_port_access(sw_ip, sw_user, sw_pwd, sw_port, vlan)
            return 200
        except Exception as e:
            em = "config l2 switch error ip: <{0}> msg: <{1}>".format(sw_ip, e)
            logger.warn(em)
            return 500

    def delete(self):
        try:
            if not self.result.get("success"):
                return self.result
            network_id = self.args.get('network_id').strip()
            sw_ip = self.args.get('sw_ip').strip()
            sw_port = self.args.get('sw_port').strip()
            sw_pwd = self.args.get('sw_pwd').strip()
            sw_user = self.args.get('sw_user').strip()
            network = Network.query.filter(Network.network_id == network_id).first()
            if not network:
                em = "can not fond network. id: <{0}>".format(network_id)
                logger.warn(em)
                return 400
            ConfigureL2Switch.set_port_access(sw_ip, sw_user, sw_pwd, sw_port, vlan=4094)
        except Exception as e:
            em = "config l2 switch error ip: <{0}> msg: <{1}>".format(sw_ip, e)
            logger.warn(em)
            return 500

    @staticmethod
    def set_port_access(sw_ip, sw_user, sw_pwd, sw_port, vlan):
        sw_obj = SwitchConfig(ip=sw_ip, port=23, username=sw_user, password=sw_pwd, timeout=5)
        sw_obj.set_access(sw_port, vlan)

    @staticmethod
    def set_port_down(sw_ip, sw_user, sw_pwd, sw_port):
        sw_obj = SwitchConfig(ip=sw_ip, port=23, username=sw_user, password=sw_pwd, timeout=5)
        sw_obj.set_down(sw_port)

    @staticmethod
    def set_port_up(sw_ip, sw_user, sw_pwd, sw_port):
        sw_obj = SwitchConfig(ip=sw_ip, port=23, username=sw_user, password=sw_pwd, timeout=5)
        sw_obj.set_up(sw_port)
