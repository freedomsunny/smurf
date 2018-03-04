# -*- encoding:utf-8 -*-
import os

# SDN Switch overlay ip address
overlay_ip ="10.20.30.254"
# controler_host = '172.16.68.106'
controler_host = '10.200.100.8'
keystone_auth_port = 5000
neutron_api_port = 9696
vlan_range = (3000, 4001)
my_sdn_switch_ip = ['172.16.101.251', '172.16.101.252']
# my_sdn_switch_ip = ['172.16.66.254']
my_sdn_switch_port = '80'
my_sdn_switch_user = 'centec'
my_sdn_switch_password = 'centec'
neutron_db_password = ""
# swarm_scheduling_host = '10.200.100.35'
# neutron_db_password = ""
swarm_scheduling_host = '172.16.68.75'
swarm_scheduling_port = 4000
keystone_ep = "http://%s:35357/v3" % controler_host
network_ep = "http://{0}:{1}/v2.0/networks".format(controler_host, neutron_api_port)
cached_backend = 'redis://127.0.0.1:6379/0'
cache_timeout = '3600'
smurf_db_password = ""
smurf_db_username = "smurf"
# smurf_db_password = "smurf"
# smurf_db = "10.200.100.8"
smurf_db = "10.200.100.35"

# flow_control_api_port = 8914
# flow_control_ep = "http://{0}:{1}/network/flowoperation_ser".format(controler_host, flow_control_api_port)
# openstack admin user and password
username = "admin"
password = ""
tenant = "admin"
# admin token endpoint
keystone_admin_endpoint = 'http://{0}:{1}/v2.0'.format(controler_host, keystone_auth_port)
# 计费平台API
charging_ep = ""


# do not change

YML_PATH = '/data/smurf/projects'
# DATABASE_URI = 'sqlite:////tmp/smurf.db'
OPENSTACK_DATABASE_URI = 'mysql+mysqlconnector://neutron:{0}@{1}/neutron?charset=utf8'.format(neutron_db_password,
                                                                                              controler_host)
DATABASE_URI = 'mysql+mysqlconnector://{0}:{1}@{2}/smurf?charset=utf8'.format(smurf_db_username,
                                                                              smurf_db_password,
                                                                              smurf_db)
db_uri = os.environ.get('DATABASE_URI')
if db_uri:
    DATABASE_URI = db_uri
DOCKER_REGISTRY = "registry.yz-dev-rrcloud.priv"
docker_registry = os.environ.get('DOCKER_REGISTRY')
if docker_registry:
    DOCKER_REGISTRY = docker_registry
