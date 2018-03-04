#!/usr/bin/env python
# encoding: utf-8

import pyjsonrpc
import smurf.config as config
from pyjsonrpc import rpcerror
import json
import logging

logger = logging.getLogger(__name__)


class PyjsonrpcClient(object):
    client = None

    def __init__(self, ip=None, port=config.my_sdn_switch_port, username=config.my_sdn_switch_user,
                 password=config.my_sdn_switch_password):
        self.client = pyjsonrpc.HttpClient(
            url="http://{0}:{1}/command-api".format(ip, port),
            username=username,
            password=password
        )

    def send_command(self, cmd_list, fmt="text", version=1):
        cmds = {}
        cmds["cmds"] = cmd_list
        cmds["format"] = fmt
        cmds["version"] = version
        # save configuration
        save_cmd = ["end", "write"]
        cmds["cmds"] += save_cmd
        try:
            response = self.client.call("executeCmds", cmds)
            return response
        except Exception, e:
            em = 'error happend sending cmd: %s, reason: %s' % (cmd_list, str(e.reason))
            logger.info(em)
            return {"error": [{"code": 500, "msg": "{0}".format(em)}]}

    def add_port_trunk(self, vni, vlan):
        pass

    def add_vni_mapping(self, vlan, vni, vtep):
        """
        method to add vlan to vni mapping on sdn switch
        """
        cmd = ["configure terminal",
               "vlan database",
               "vlan {0}".format(vlan),
               "vlan {0} overlay enable".format(vlan),
               "exit",
               "overlay",
               "vlan {0} vni {1}".format(vlan, vni),
               "vlan {0} remote-vtep {1}".format(vlan, vtep)]
        ret = self.send_command(cmd)
        return ret

    def delete_vni_mapping(self, vlan, vtep):
        """
        method to delete vlan to vni mapping to sdn switch
        """
        cmd = ["config t",
               "overlay",
               "no vlan {0} remote-vtep {1} ".format(vlan, vtep),
               "no vlan {0} vni".format(vlan),
               "end",
               "config t",
               "vlan database",
               "vlan {0} overlay disable".format(vlan)
               ]

        ret = self.send_command(cmd)
        return ret

    def allow_vlan_pass(self):
        pass

    def save_config(self):
        cmd = ["end",
               "write"
               ]
        ret = self.send_command(cmd)
        return ret

    def get_vteps(self):
        """
        method to get vtep index and vtep ipaddress from sdn switch
        """
        cmd = ["show overlay remote-vtep"]
        result = self.send_command(cmd)
        if "'errorCode'" not in result[0].keys():
            vxlans = [i.split() for i in [i for i in result[0]['sourceDetails'].split('\n') if 'VxLAN' in i]]
            data = {}
            for i in vxlans:
                vtep_index, tun_type, virt_mac, vtep_ip, source_ip, SplitH = i
                data[vtep_index] = vtep_ip
            return data
        else:
            em = "get vteps error {0}".format(result[0]["errorDesc"])
            return {"error": [{"code": 401, "msg": "{0}".format(em)}]}
