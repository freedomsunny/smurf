#!encoding=utf-8
import json
import logging
import os
import re
import shutil
import uuid
import time

import docker
import fcntl
import ruamel.yaml
import yaml
from threading import Thread
from collections import OrderedDict

import smurf.auth as auth
from smurf.utils import random_mac
from flask import g, request
from flask_restful import Resource, reqparse, marshal
from smurf.bridge import get_project, ProjectWrapper
from smurf.db.models import db_session, ServiceTemplate, Project, Service, User, UserGroup, ProjectUserRef, \
    ProjectUserGroupRef, Network, UserGroupUserRef, VlanIpAddress, ServiceTemplateDepends, Containers, \
    ComposeTemplateRef
from smurf.resources.network import GetPortAbout, delete_port, get_subnet, VlanNetworkManager
from sqlalchemy import and_, literal

from smurf.api_requests.api_requests import get_http, post_http, delete_http, put_http
from smurf.api_requests.sdn_switch_config import PyjsonrpcClient
import smurf.config as config
from .common import PROJECT_FIELDS, PROJECT_USER_FIELDS, PROJECT_USER_GROUP_FIELDS, PROJECT_ROLE_MANAGER, \
    PROJECT_ROLE_GUEST, PROJECT_ROLES

logger = logging.getLogger(__name__)


def build_project_networks(services):
    networks = {}
    for name, service in services.items():
        if service.get('networks'):
            for network in service.get('networks'):
                if network not in networks and network != 'default':
                    networks[network] = {'external': True}
    return networks


def populate_project_services(project):
    project.services = Service.query.filter(Service.project_id == project.id).all()
    for service in project.services:
        populate_project_service(service)


def populate_project_service(service):
    service_data = json.loads(service.data)
    service_template = ServiceTemplate.query.filter(ServiceTemplate.id == service.template_id).first()
    service_template_data = json.loads(service_template.yml)
    service_template.service = service_template_data.get('service')
    service_template.environment = service_template_data.get('environment')
    service.hostname = service_data.get('hostname')
    service.environment = service_data.get('environment')
    service.command = service_data.get('command')
    service.networks = service_data.get('networks')
    service.service_template = service_template


def setup_project_yml(project):
    services = Service.query.filter(Service.project_id == project.id).all()
    # project_config = ruamel.yaml.load("version: '2'", ruamel.yaml.RoundTripLoader)
    project_config = {"version": '2'}
    service_configs = {}
    for service in services:
        service_data = json.loads(service.data)
        service_template = ServiceTemplate.query.filter(ServiceTemplate.id == service.template_id).first()
        service_template_data = json.loads(service_template.yml)
        service_config = {'image': service_template_data.get('image')}
        if service_data.get('hostname'):
            service_config['hostname'] = service_data.get('hostname')
        environment = service_data.get('environment')
        if environment:
            # environment.update(service_data.get('environment'))
            service_config['environment'] = environment
        if service_template_data.get("environment"):
            environment.update(service_template_data.get('environment'))
        # if service_data.get('command'):
        if service_template_data.get("command"):
            service_config['command'] = service_template_data.get('command')
        if service_template_data.get("volumes"):
            service_config['volumes'] = service_template_data.get('volumes')
        if service_data.get('restart'):
            service_config['restart'] = service_data.get('restart')
        if service_data.get('networks'):
            service_config['networks'] = service_data.get('networks')
        if service_data.get("mac_address"):
            service_config["mac_address"] = service_data.get("mac_address")
        if service_data.get("mem_limit"):
            service_config["mem_limit"] = service_data.get("mem_limit")
        if service_data.get("memswap_limit"):
            service_config["memswap_limit"] = service_data.get("memswap_limit")
        service_configs[service.name] = service_config
        # service_configs = {}
    project_config['services'] = service_configs
    project_config['networks'] = build_project_networks(service_configs)
    project_dtail = get_project_detail(project_config, project)
    if not project_dtail[0]:
        return False, project_dtail[1]
    # project_yml = ruamel.yaml.dump(project_config, Dumper=ruamel.yaml.RoundTripDumper, default_flow_style=False)
    project_yml = ordered_dump(project_config, Dumper=yaml.SafeDumper, default_flow_style=False)
    return project_yml, project_dtail[1]


def ordered_dump(data, stream=None, Dumper=yaml.Dumper, **kwds):
    class OrderedDumper(Dumper):
        pass

    def _dict_representer(dumper, data):
        return dumper.represent_mapping(
            yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
            data.items())
    OrderedDumper.add_representer(OrderedDict, _dict_representer)
    return yaml.dump(data, stream, OrderedDumper, **kwds)


def get_project_detail(project_config, project):
    try:
        services = project_config.get("services")
        password_keys = ["REDIS_PASSWORD", "MARIADB_ROOT_PASSWORD", "RABBITMQ_PASSWORD"]
        username_keys = ["RABBITMQ_USER"]
        all_details = []
        # the `k` is service name. the v is the values
        for k, v in services.iteritems():
            details = {}
            service_name = k[:-8].strip()
            details["name"] = service_name
            # get project's password. the all containers password is the same
            for password_key in password_keys:
                password = v.get("environment").get(password_key)
                if password:
                    details["password"] = password
            # get project's username. the all containers username is the same
            for username_key in username_keys:
                username = v.get("environment").get(username_key)
                if username:
                    details["user_name"] = username
            # get project's ip address
            if v.get("networks"):
                ip_address = v.get("networks").values()[0].get("ipv4_address")
                details["ip_address"] = ip_address
            all_details.append(details)
            all_details = json.dumps(all_details)
        return True, all_details
    except Exception as e:
        em = "can not get project details. project id: <{0}>. msg: <{1}>".format(project.id, e)
        logger.warn(em)
        return False, 500


def get_compose_project_name(project_name, user_name):
    # Docker-compose changes project_name to lower case, and removes letters except [a-z0-9]
    return re.sub(r'0', '0z', user_name.lower()) + '00' + re.sub(r'[^a-z0-9]', '', project_name.lower())


def get_project_path(project, user_name):
    directory = config.YML_PATH + '/' + user_name + '/' + project.name
    if not os.path.isdir(directory):
        os.makedirs(directory)
    return directory


# get compose project object from compose yml file
def get_compose_project(project, user_name):
    directory = get_project_path(project, user_name)
    project_name = get_compose_project_name(project.name, user_name)
    compose_project = get_project(directory, project_name=project_name)
    return compose_project


def save_project_yml(project, user_name):
    directory = get_project_path(project, user_name)
    file_path = directory + "/docker-compose.yml"
    with open(file_path, "w") as compose_yml:
        compose_yml.write(project.yml)


def need_restore_project_yml(project, user_name):
    directory = get_project_path(project, user_name)
    yml_path = directory + "/dostandalonecker-compose.yml"
    return not os.path.exists(yml_path)


def restore_project_ymls(user_name):
    """
    restore docker-compose.yml from db for all projects if needed.
    """
    logger.info("Restoring project ymls ...")
    projects = Project.query.all()
    if not projects:
        logger.info("No projects found")
        return

    # Get the lock to restore since gunicorn starts N processes
    lock_file = "/var/tmp/smurf_lock"
    with open(lock_file, 'w') as file:
        fcntl.flock(file.fileno(), fcntl.LOCK_EX)

        for project in projects:
            if need_restore_project_yml(project, user_name):
                save_project_yml(project, user_name)
    logger.info("Restored project ymls ...")


def get_project_auth(project_id, user):
    if user.type == 'Admin':
        return PROJECT_ROLE_MANAGER

    effective_role = None
    owner_projects = db_session.query(Project, literal(PROJECT_ROLE_MANAGER).label('role')).filter(
        and_(Project.user_id == user.id, Project.id == project_id))
    user_projects = db_session.query(Project, ProjectUserRef.role).join(ProjectUserRef,
                                                                        ProjectUserRef.project_id == Project.id).filter(
        and_(ProjectUserRef.user_id == user.id, Project.id == project_id))
    group_projects = db_session.query(Project, ProjectUserGroupRef.role).join(ProjectUserGroupRef,
                                                                              ProjectUserGroupRef.project_id == Project.id). \
        join(UserGroup, UserGroup.id == ProjectUserGroupRef.user_group_id). \
        join(UserGroupUserRef, UserGroupUserRef.group_id == UserGroup.id).filter(
        and_(UserGroupUserRef.user_id == user.id, Project.id == project_id, UserGroup.removed == None))
    project_auths = owner_projects.union(user_projects).union(group_projects).all()
    if not project_auths:
        return None
    for project, role in project_auths:
        if role == PROJECT_ROLE_MANAGER:
            return PROJECT_ROLE_MANAGER
        else:
            effective_role = PROJECT_ROLE_GUEST

    return effective_role


def check_service_networks(s_name, networks, allowed_external_nets):
    for net_name in networks:
        if net_name not in allowed_external_nets:
            em = 'Invalid {0} network {1}'.format(s_name, net_name)
            logger.info(em)
            return False
    return True


class ProjectActionAPI(auth.X_resource):
    def post(self, project_id, action):
        """
        method to up a project
        """
        if not self.result.get("success"):
            return self.result
        user_name = self.context.get('user_name')
        user_id = self.context.get('user_id')

        project = Project.query.filter(Project.id == project_id).first()
        if not project:
            em = 'Invalid project id ' + str(project_id)
            logger.info(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
        if action == "up":
            # return self.up(project, user_name, user_id)
            return self.up_1(project, user_name, user_id)
        if action == "down":
            return self.down_1(project, user_name, user_id)
        em = "unsported action"
        return {"error": [{"code": 400, "msg": "{0}".format(em)}]}

    def up_1(self, project, user_name, user_id):
        task = Thread(target=lambda: self.up(project, user_name, user_id))
        task.setDaemon(True)
        task.start()
        return 202

    def down_1(self, project, user_name, user_id):
        task = Thread(target=lambda: self.down(project, user_name, user_id))
        task.setDaemon(True)
        task.start()
        return 202

    def up(self, project, user_name, user_id):
        try:
            logger.info("Regenerate project yml ...")
            # Always regenerate project yml since template may be changed after last up
            project_yml, project_detail = setup_project_yml(project)
            if project_yml != project.yml:
                Project.query.filter(Project.id == project.id).update({'yml': project_yml})
                db_session.commit()
            save_project_yml(project, user_name)

            compose_project = get_compose_project(project, user_name)

            # before start project we must create network first. add by huangyingjun
            services = compose_project.get_services()
            # used container is len(services)
            used_container = len(services)
            # get every service's used network name
            network_names = set()
            for service in services:
                network_dict = service.networks
                if network_dict:
                    for network in network_dict:
                        network_names.add(network)
            # create network
            for network_name in network_names:
                # first check network is it created from db
                network = Network.query.filter(and_(Network.subnet_id == network_name,
                                                    Network.user_id == user_id)).first()
                # if network is not created . so we create external network
                if network and not network.iscreated:
                    # user's subnet id is the docker network name
                    net_name = network.subnet_id
                    ret = VlanNetworkManager.create_network(network.cidr,
                                                            network.vlan,
                                                            net_name,
                                                            network.gateway)

                    if ret.get("error"):
                        em = "create network error name: <{0}>. msg: <{1}>".format(net_name, ret[1])
                        logger.info(em)
                    # last update db's network created status
                    Network.query.filter(and_(Network.user_id == user_id,
                                              Network.subnet_id == network_name)).update({Network.iscreated: True})
                    msg = "update network status to db"
                    logger.info(msg)

                    # config the SDN switch
                    # first get all vteps from sdn switch
                    for switch_ip in config.my_sdn_switch_ip:
                        sdn_switch_obj = PyjsonrpcClient(switch_ip.strip())

                        vteps = sdn_switch_obj.get_vteps()
                        if vteps.get("error"):
                            return vteps
                        for vtep_index, vtep_ip in vteps.iteritems():
                            sdn_switch_obj.add_vni_mapping(network.vlan, network.vni, vtep_index)
                            msg = "config sdn switch <------> <{0}>".format(switch_ip)
                            logger.info(msg)
                    db_session.commit()
            # 创建网络太快，会异常 add by huangyingjun 2017/08/18
            time.sleep(1)
            project_adapter = ProjectWrapper(compose_project)
            containers = project_adapter.up()
            Project.query.filter(Project.id == project.id).update({Project.state: 'active'})
            # insert containers info to database add by huangyingjun
            project_id = project.id
            for container in containers:
                container_info = container.inspect()
                uid = str(uuid.uuid1())
                name = container_info.get('Name')[1:]
                id = container_info.get('Id')
                status = container_info.get('State').get("Status")

                container_db = Containers(uid, name, id, status, user_name, project_id)
                db_session.add(container_db)
                db_session.flush()
            db_session.commit()
            logger.info("%s upped, compose project %s", project, compose_project.name)
        except Exception as e:
            db_session.rollback()
            logger.warn(str(e))
            return {"error": [{"code": 400, "msg": "{0}".format(e)}]}

        populate_project_services(project)
        for service in project.services:
            service.containers = [c for c in containers if c.service == service.name]

        # send order to charging API. beging charging
        charging(project.resource, used_container, project.id, user_id, user_name,
                 self.context.get("project").get("id"), self.token)
        return marshal(project, PROJECT_FIELDS, envelope="project")

    def down(self, project, user_name, user_id):
        if project.state != 'created':
            try:
                compose_project = get_compose_project(project, user_name)
                compose_project.down(None, True)

                # when shutdown project we need recycling  by huangyingjun
                services = compose_project.get_services()
                for service in services:
                    network_dict = service.networks
                    if network_dict:
                        for network in network_dict:
                            # get network's id
                            networks_db = Network.query.filter(and_(Network.user_id == user_id,
                                                                    Network.subnet_id == network)).first()

                            # check network is it used on Containers. first get network's id
                            docker_client = docker.APIClient()
                            docker_networks = docker_client.networks()
                            network_used_container = None
                            for s in docker_networks:
                                network_name = s.get('Name', None)
                                if network_name == network and network_name:
                                    network_used_container = s.get('Containers', None)
                            # if network not in used on Containers. so we can remove it
                            if not network_used_container:
                                if networks_db.iscreated:
                                    net_name = networks_db.subnet_id
                                    ret = VlanNetworkManager.delete_network(net_name)
                                    if ret.get("error"):
                                        return ret
                                    # last update db's network created status
                                    Network.query.filter(and_(Network.user_id == user_id,
                                                              Network.subnet_id == network)).update(
                                        {Network.iscreated: False})
                                    db_session.commit()
                                    # config sdn switch
                                    for switch_ip in config.my_sdn_switch_ip:
                                        sdn_switch_obj = PyjsonrpcClient(switch_ip)
                                        vteps = sdn_switch_obj.get_vteps()
                                        if vteps.get("error"):
                                            return vteps
                                        for vtep_index, vtep_ip in vteps.iteritems():
                                            sdn_switch_obj.delete_vni_mapping(networks_db.vlan, vtep_index)

                # remove Containers info from db
                projects_containers = Containers.query.filter(and_(Containers.owner == user_name,
                                                                   Containers.project_id == project.id)).all()
                if projects_containers:
                    for projects_container in projects_containers:
                        db_session.delete(projects_container)
                        db_session.flush()

                # delete containers info from database .add by huangyingjun
                Project.query.filter(Project.id == project.id).update({Project.state: 'inactive'})
                db_session.commit()
                logger.info("%s downed, compose project %s", project, compose_project.name)
            except Exception as e:
                db_session.rollback()
                logger.warn("Unable to down project: %s", e)
                return {"error": [{"code": 500, "msg": "{0}".format(e)}]}

        charging(project.resource, "", project.id, user_id, user_name,
                 self.context.get("project").get("id"), self.token)
        populate_project_services(project)
        return marshal(project, PROJECT_FIELDS, envelope="project")


class ProjectListAPI(auth.X_resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument("name", type=unicode, location="json")
        self.reqparse.add_argument("description", type=unicode, location="json")
        self.reqparse.add_argument("services", type=list, location="json")
        super(ProjectListAPI, self).__init__()

    def get(self):
        """
        method to get Project list
        """
        if not self.result.get("success"):
            return self.result
        user_id = self.context.get('user_id')
        user_name = self.context.get('user_name')
        projects = self.query_projects(user_id)
        for project in projects:
            populate_project_services(project)
            real_state = 'inactive'
            if project.state != 'created':
                try:
                    compose_project = get_compose_project(project, user_name)
                    containers = compose_project.containers(stopped=True)
                    for container in containers:
                        ip = container.get('NetworkSettings.IPAddress')
                        if not ip:
                            networks = container.get('NetworkSettings.Networks')
                            ip = networks.items()[0][1].get('IPAddress')
                            if len(networks) > 1:
                                defualt_net_name = container.labels.get('com.docker.compose.project') + '_default'
                                for net in networks:
                                    if net != defualt_net_name:
                                        ip = networks[net].get('IPAddress')
                                        break
                        container.ip = ip
                except Exception as e:
                    logger.warn('Unable to get containers of %s: %s', project, e)
                    continue
                for service in project.services:
                    service.containers = [c for c in containers if c.service == service.name]
                    service.state = 'inactive'
                    for c in service.containers:
                        c.status = c.get('State.Status')
                        if c.is_running:
                            service.state = 'active'
                            real_state = 'active'
                            break
                if real_state != project.state:
                    try:
                        logger.info('Project state in db: %s, real: %s', Project.state, real_state)
                        Project.query.filter(Project.id == project.id).update({Project.state: real_state})
                        db_session.commit()
                    except Exception as e:
                        db_session.rollback()
                        logger.warn('Unable to change state of %s: %s', project, e)
                        continue

        return {"projects": [marshal(project, PROJECT_FIELDS) for project in projects]}

    def post(self):
        """
        method to add a Project
        """
        if not self.result.get("success"):
            return self.result

        user_id = self.context.get('user_id')
        user_name = self.context.get('user_name')
        project_name = self.args.get('name')
        description = self.args.get('description')
        use_network = self.args.get('use_network')
        template_compose_id = self.args.get('template_compose_id')
        template_compose_name = self.args.get('template_compose_name')
        environment = self.args.get('environment')
        # services = self.args.get("services")
        services = []
        service = {}
        # check project name is it exist
        exist_project = Project.query.filter(and_(Project.name == project_name,
                                                  Project.user_id == user_id)).first()
        if exist_project:
            em = "project  <{0}> is already exist at user: <{1}>".format(project_name, user_name)
            logger.warn(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}

        # check project name is it valid
        ret = self.validate_project_name(project_name, user_name, user_id)
        if not ret.get('success'):
            logger.warn(ret.get("error")[0].get('msg'))
            return ret

        template_compose_ids = ComposeTemplateRef.query.filter(ComposeTemplateRef.compose_id == template_compose_id).all()

        if not template_compose_ids:
            em = "can not fond template compose id: <{0}>".format(template_compose_id)
            logger.warn(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}

        # 随机生成名字
        for template_compose_id in template_compose_ids:
            service_template = ServiceTemplate.query.filter(ServiceTemplate.id == template_compose_id.template_id).first()
            name = service_template.name + str(uuid.uuid1())[:8]
            mac_address = random_mac()
            service['name'] = name
            service["template_id"] = template_compose_id.template_id
            service["networks"] = {use_network: {}}
            service["mac_address"] = mac_address
            service["mem_limit"] = self.args.get("mem_limit", "1g")
            service["memswap_limit"] = self.args.get("memswap_limit", "1g")
            if environment:
                service["environment"] = environment

            services.append(service)
        if not services:
            em = 'No services defined'
            logger.info(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
        service_names = []
        # get network name by user's id
        all_networks = Network.query.filter(Network.user_id == user_id).all()
        if not all_networks:
            allowed_external_nets = []
        else:
            allowed_external_nets = [network.subnet_id for network in all_networks if network.user_id == user_id]
        service_depends = []
        template_id_depends = []
        template_ids = []
        service_depend = {}
        for s in services:
            template_id = s.get("template_id")
            template_ids.append(template_id)

            # not template_depends
            template_depends = ServiceTemplateDepends.query.filter(
                ServiceTemplateDepends.template_id == template_id).all()
            for service_template_depend in template_depends:
                # 如果依赖的模板ID在里面的话，就不做任何事情。反之如果在里面的话就从数据库中查找出来添加到yml里面
                if service_template_depend.template_id_depend not in template_id_depends:
                    template_id_depends.append(service_template_depend.template_id_depend)
                    template_depend = ServiceTemplate.query.filter(
                        ServiceTemplate.id == service_template_depend.template_id_depend).first()
                    service_template_data = json.loads(template_depend.yml)
                    service_depend["template_id"] = template_depend.id
                    if service_template_data.get("service"):
                        service_depend["name"] = service_template_data.get("service")
                    if service_template_data.get("environment"):
                        service_depend["environment"] = service_template_data.get("environment")
                    if service_template_data.get("hostname"):
                        service_depend["hostname"] = service_template_data.get("hostname")
                    service_depend["restart"] = "always"
                    # service_depend["networks"] = {"default": {}}
                    service_depends.append(service_depend)

        for service_depend in service_depends:
            template_id = service_depend.get("template_id")
            if template_id not in template_ids:
                services.append(service_depend)

        # check service name and template is it exist by template id
        for s in services:
            s_name = s.get("name")
            if (s_name is None) or (type(s_name) is not unicode) or (not re.match('^[a-zA-Z0-9._-]+$', s_name)):
                em = 'Invalid service name {0}'.format(s_name)
                logger.info(em)
                return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
            # check container name is it Duplicated
            if s_name in service_names:
                em = 'Duplicated service name {0}'.format(s_name)
                logger.info(em)
                return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
            template_id = s.get("template_id")
            # check template is it exist
            template = ServiceTemplate.query.filter(ServiceTemplate.id == template_id).first()
            if not template:
                em = 'Invalid template id {0}'.format(template_id)
                logger.info(em)
                return {"error": [{"code": 400, "msg": "{0}".format(em)}]}

            # check network name is it exist and is it valid
            networks = s.get("networks")
            if networks:
                em = check_service_networks(s_name, networks, allowed_external_nets)
                if not em:
                    return False

            service_names.append(s_name)

        project = Project(project_name, description, user_id, resource=template_compose_name)

        try:
            db_session.add(project)
            db_session.flush()

            for s in services:
                data = {'name': s.get("name")}
                if s.get("hostname"):
                    data['hostname'] = s.get("hostname")
                if s.get('environment'):
                    data['environment'] = s.get("environment")
                if s.get("command"):
                    data["command"] = s.get("command")
                if s.get("mac_address"):
                    data["mac_address"] = s.get("mac_address")
                if s.get("mem_limit"):
                    data["mem_limit"] = s.get("mem_limit")
                if s.get("memswap_limit"):
                    data["memswap_limit"] = s.get("memswap_limit")
                data["restart"] = s.get("restart", "always")
                template_id = s.get("template_id")
                # every container only can be use a single network
                # get every network's name
                for n_name in s.get("networks"):

                    network_s = [network_s for network_s in all_networks if network_s.user_id == user_id and
                                 network_s.subnet_id == n_name]
                    if not network_s:
                        em = "can not found network info with network name: <{0}>. user id: <{1}>".format(n_name,
                                                                                                          user_id)
                        return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
                    openstack_network_id = network_s[0].network_id
                    openstack_subnet_id = network_s[0].subnet_id
                    # assign  network's ip address from openstack neutron
                    ret = GetPortAbout(openstack_network_id, openstack_subnet_id, data.get("mac_address"),
                                       self.context.get("project").get("id"))
                    if ret.get("error"):
                        return ret
                    ipaddress = ret.get('port').get('fixed_ips')[0].get('ip_address')
                    port_id = ret.get('port').get('id')
                    if ipaddress:
                        # update template's network config
                        if s.get("networks"):
                            data["networks"] = s.get("networks")
                            data['networks'][n_name] = {'ipv4_address': ipaddress}
                        """
                        # 添加openstack流规则 add by huangyingjun 20170817
                        req_data = {"ip": ipaddress,
                                    "mac": data.get("mac_address"),
                                    "network_id": openstack_network_id
                                    }
                        req_data = json.dumps(req_data)
                        ret = post_http(url=config.flow_control_ep, data=req_data)
                        if ret.status_code != 200:
                            return {"code": 500, "msg": "can not add openstack flow table"}
                        """
                    else:
                        em = "can not assign ip address from openstack with \
                        network id : {0}  sub_net id {1}".format(openstack_network_id,
                                                                 openstack_subnet_id)
                        return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
                    service = Service(s["name"], project.id, template_id, json.dumps(data))

                    db_session.add(service)
                    db_session.flush()
                    s['id'] = service.id
                    VlanIpadd = VlanIpAddress(ipaddress, network_s[0].id, service.id, user_id, port_id)
                    db_session.add(VlanIpadd)
                    db_session.flush()

            project.services = services
            project_yml, project_detail = setup_project_yml(project)
            if not project_yml:
                return {"code": 500, "msg": "Unable to create project. project id: <{0}>".format(project.id)}
            Project.query.filter(Project.id == project.id).update({Project.yml: project_yml,
                                                                   Project.detail: project_detail})
            db_session.commit()
            save_project_yml(project, user_name)
            logger.info('%s created', project)
        except Exception as e:
            db_session.rollback()
            em = "Unable to create project: %s" % e
            logger.warn(em)
            return {"error": [{"code": 500, "msg": "{0}".format(em)}]}

        return {"code": 200, "msg": ""}
        # return marshal(project, PROJECT_FIELDS, envelope="project")

    def validate_project_name(self, project_name, user_name, user_id):
        if project_name is None or not re.match('^[a-z0-9][a-z_0-9]+$', project_name):
            em = 'Project name {0} is not valid'.format(project_name)
            return {"error": [{"code": 401, "msg": "{0}".format(em)}]}
        exist_projects = Project.query.filter(Project.user_id == user_id).first()
        if exist_projects:
            em = "project <{0}> is exist".format(project_name)
            return {"error": [{"code": 401, "msg": "{0}".format(em)}]}

        return {"success": [{"code": 200, "msg": ""}]}

    def query_projects(self, user_id):
        owner_projects = Project.query.filter(Project.user_id == user_id)
        user_projects = db_session.query(Project).join(ProjectUserRef, ProjectUserRef.project_id == Project.id).filter(
            ProjectUserRef.user_id == user_id)
        group_projects = db_session.query(Project).join(ProjectUserGroupRef,
                                                        ProjectUserGroupRef.project_id == Project.id). \
            join(UserGroup, UserGroup.id == ProjectUserGroupRef.user_group_id). \
            join(UserGroupUserRef, UserGroupUserRef.group_id == UserGroup.id).filter(
            and_(UserGroupUserRef.user_id == user_id, UserGroup.removed == None))
        projects = owner_projects.union(user_projects).union(group_projects).all()
        return projects


class ProjectAPI(auth.X_resource):
    def get(self, project_id):
        """
        method to get project
        :param project_id: 
        :return: 
        """
        if not self.result.get("success"):
            return self.result

        include_containers = False
        include = request.args.get('include')
        if 'containers' == include:
            include_containers = True
        project = Project.query.filter(Project.id == project_id).first()
        if project is None:
            return {}
        if 'active' == project.state:
            include_containers = True
        populate_project_services(project)

        if include_containers:
            compose_project = get_compose_project(project)
            containers = compose_project.containers()
            for service in project.services:
                service.containers = [c for c in containers if c.service == service.name]
        return marshal(project, PROJECT_FIELDS, envelope="project")

    def delete(self, project_id):
        """
        method to delete a project
        :param project_id: 
        :return: 
        """
        if not self.result.get("success"):
            return self.result

        user_id = self.context.get('user_id')
        user_name = self.context.get('user_name')
        token = self.token
        project = Project.query.filter(and_(Project.user_id == user_id, Project.id == project_id)).first()
        if not project:
            em = 'can not found for project {0}'.format(project_id)
            logger.info(em)
            return {"error": [{"code": 401, "msg": "{0}".format(em)}]}
        try:
            if project.state != 'created':
                # Project should be downed to get resources recycled regardless of it's state.
                # Project network might be created even if it is not successfully upped.
                # get project compose object
                compose_project = get_compose_project(project, user_name)
                logger.info('Down the compose project %s', compose_project.name)
                compose_project.down(None, True)
            # get project's all service
            services = Service.query.filter(Service.project_id == project_id).all()
            # first delete port from OpenStack
            for service in services:
                vlan_info = VlanIpAddress.query.filter(and_(VlanIpAddress.service_id == service.id,
                                                            VlanIpAddress.user_id == user_id)).first()
                ret = delete_port(token, vlan_info.port_id)
                if not ret.get('success'):
                    logger.warn("Error.....delete port from OpenStack error. port id: <{0}>. ".format(vlan_info.port_id))
                # so remove ip address about info
                VlanIpAddress.query.filter(and_(VlanIpAddress.service_id == service.id,
                                                VlanIpAddress.user_id == user_id)).delete()
                db_session.flush()

            Service.query.filter(Service.project_id == project_id).delete()
            Containers.query.filter(Containers.project_id == project_id).delete()
            ProjectUserRef.query.filter(ProjectUserRef.project_id == project_id).delete()
            ProjectUserGroupRef.query.filter(ProjectUserGroupRef.project_id == project_id).delete()
            db_session.delete(project)
            db_session.commit()
            directory = get_project_path(project, user_name)
            shutil.rmtree(directory)
            logger.info('%s deleted', project)
        except Exception as e:
            db_session.rollback()
            logger.info('Unable to delete project: %s', e)
            return {"error": [{"code": 401, "msg": "{0}".format(e)}]}

        return {"code": 200, "msg": ""}


class ProjectUserListAPI(Resource):
    def get(self, project_id):
        """
        method to get Project authorized user list
        """
        if not check_project_auth(project_id, g.user, PROJECT_ROLE_GUEST):
            em = 'No auth for project {0}'.format(project_id)
            logger.info(em)
            return {}
        project = Project.query.filter(Project.id == project_id).first()
        if project is None:
            em = 'Invalid project id ' + str(project_id)
            logger.info(em)
            return {}

        users = db_session.query(User, ProjectUserRef.role). \
            join(ProjectUserRef, ProjectUserRef.user_id == User.id). \
            filter(ProjectUserRef.project_id == project_id).all()
        user_auths = [{
            'id': user.id,
            'name': user.name,
            'cname': user.cname,
            'type': user.type,
            'role': role
        } for user, role in users]
        return marshal(user_auths, PROJECT_USER_FIELDS, envelope='users')

    def put(self, project_id):
        """
        method to set Project authorized user list
        """
        project = Project.query.filter(Project.id == project_id).first()
        if project is None:
            em = 'Invalid project id {0}'.format(project_id)
            logger.info(em)
            return {'ec': 1, 'em': em}
        if not check_project_auth(project_id, g.user, PROJECT_ROLE_MANAGER):
            em = 'No auth to set project {0} user auth'.format(project_id)
            logger.info(em)
            return {'ec': 1, 'em': em}

        users = request.get_json()
        if users is None:
            em = 'Invalid request data'
            logger.info(em)
            return {'ec': 1, 'em': em}
        for user_id in users:
            user = User.query.filter(User.id == user_id).first()
            if not user:
                em = 'Invalid user id {0}'.format(user_id)
                logger.info(em)
                return {'ec': 1, 'em': em}
            role = users[user_id]
            if role not in [PROJECT_ROLE_MANAGER, PROJECT_ROLE_GUEST]:
                em = 'Invalid role {0}'.format(role)
                logger.info(em)
                return {'ec': 1, 'em': em}

        try:
            ProjectUserRef.query.filter(ProjectUserRef.project_id == project_id).delete()
            for user_id in users:
                ref = ProjectUserRef(project_id, user_id, users[user_id])
                db_session.add(ref)
            db_session.commit()
            return {'ec': 0, 'em': 'success'}
        except Exception as e:
            db_session.rollback()
            logger.warn('Unable to set project user list: %s', e)
            return {'ec': 3, 'em': str(e)}


class ProjectUserGroupListAPI(Resource):
    def __init__(self):
        pass

    def get(self, project_id):
        """
        method to get Project authorized user list
        """
        if not check_project_auth(project_id, g.user, PROJECT_ROLE_GUEST):
            em = 'No auth for project {0}'.format(project_id)
            logger.info(em)
            return {}
        project = Project.query.filter(Project.id == project_id).first()
        if project is None:
            em = 'Invalid project id {0}'.format(project_id)
            logger.info(em)
            return {}

        user_groups = db_session.query(UserGroup, ProjectUserGroupRef.role). \
            join(ProjectUserGroupRef, ProjectUserGroupRef.user_group_id == UserGroup.id). \
            filter(ProjectUserGroupRef.project_id == project_id).all()
        for group, role in user_groups:
            group.role = role
        user_group_auths = [group for group, role in user_groups]
        return marshal(user_group_auths, PROJECT_USER_GROUP_FIELDS, envelope='usergroups')

    def post(self, project_id):
        """
        method to set Project authorized user list
        """
        project = Project.query.filter(Project.id == project_id).first()
        if not project:
            em = 'Invalid project id {0}'.format(project_id)
            logger.info(em)
            return {'ec': 1, 'em': em}
        args = request.get_json()
        if args is None:
            em = 'Invalid request data'
            logger.info(em)
            return {'ec': 1, 'em': em}
        user_group_id = args.get('user_group_id')
        user_group = UserGroup.query.filter(UserGroup.id == user_group_id).first()
        if not user_group:
            em = 'Invalid user group id {0}'.format(user_group_id)
            logger.info(em)
            return {'ec': 1, 'em': em}
        role = args.get('role')
        if role not in [PROJECT_ROLE_MANAGER, PROJECT_ROLE_GUEST]:
            em = 'Invalid role {0}'.format(role)
            logger.info(em)
            return {'ec': 1, 'em': em}
        if not check_project_auth(project_id, g.user, PROJECT_ROLE_MANAGER):
            em = 'No auth to set project {0} user group auth'.format(project_id)
            logger.info(em)
            return {'ec': 1, 'em': em}
        ref = ProjectUserGroupRef.query.filter(and_(ProjectUserGroupRef.project_id == project_id,
                                                    ProjectUserGroupRef.user_group_id == user_group_id)).first()
        if ref:
            if ref.role != role:
                em = 'User group {0} role is already set'.format(user_group_id)
                logger.info(em)
                return {'ec': 1, 'em': em}
            else:
                return {'ec': 0, 'em': 'success'}

        try:
            ref = ProjectUserGroupRef(project_id, user_group_id, role)
            db_session.add(ref)
            db_session.commit()
            return {'ec': 0, 'em': 'success'}
        except Exception as e:
            db_session.rollback()
            logger.warn('Unable to set project user group list: %s', e)
            return {'ec': 3, 'em': str(e)}

    def put(self, project_id):
        """
        method to set Project authorized user list
        """
        project = Project.query.filter(Project.id == project_id).first()
        if not project:
            em = 'Invalid project id {0}'.format(project_id)
            logger.info(em)
            return {'ec': 1, 'em': em}
        usergroups = request.get_json()
        if usergroups is None:
            em = 'Invalid request data'
            logger.info(em)
            return {'ec': 1, 'em': em}
        for user_group_id in usergroups:
            user_group = UserGroup.query.filter(UserGroup.id == user_group_id).first()
            if not user_group:
                em = 'Invalid user group id {0}'.format(user_group_id)
                logger.info(em)
                return {'ec': 1, 'em': em}
            role = usergroups[user_group_id]
            if role not in PROJECT_ROLES:
                em = 'Invalid role {0}'.format(role)
                logger.info(em)
                return {'ec': 1, 'em': em}
        if not check_project_auth(project_id, g.user, PROJECT_ROLE_MANAGER):
            em = 'No auth to set project {0} user group auth'.format(project_id)
            logger.info(em)
            return {'ec': 1, 'em': em}

        try:
            ProjectUserGroupRef.query.filter(ProjectUserGroupRef.project_id == project_id).delete()
            for user_group_id in usergroups:
                ref = ProjectUserGroupRef(project_id, user_group_id, usergroups[user_group_id])
                db_session.add(ref)
            db_session.commit()
            return {'ec': 0, 'em': 'success'}
        except Exception as e:
            db_session.rollback()
            logger.warn('Unable to set project user group list: %s', e)
            return {'ec': 3, 'em': str(e)}


class ProjectUserGroupAPI(Resource):
    def __init__(self):
        pass

    def get(self, project_id, user_group_id):
        """
        method to get Project authorized user group
        """
        if not check_project_auth(project_id, g.user, PROJECT_ROLE_GUEST):
            em = 'No auth for project {0}'.format(project_id)
            logger.info(em)
            return {}
        project = Project.query.filter(Project.id == project_id).first()
        if project is None:
            em = 'Invalid project id {0}'.format(project_id)
            logger.info(em)
            return {}

        user_group_ref = ProjectUserGroupRef.query.filter(ProjectUserGroupRef.project_id == project_id,
                                                          ProjectUserGroupRef.user_group_id == user_group_id).first()
        if not user_group_ref:
            em = 'No auth found for user group {0}'.format(user_group_id)
            logger.info(em)
            return {}

        user_group = UserGroup.query.filter(UserGroup.id == user_group_id).first()
        user_group.role = user_group_ref.role
        return marshal(user_group, PROJECT_USER_GROUP_FIELDS, envelope='usergroup')

    def put(self, project_id, user_group_id):
        project = Project.query.filter(Project.id == project_id).first()
        if not project:
            em = 'Invalid project id {0}'.format(project_id)
            logger.info(em)
            return {'ec': 1, 'em': em}
        ref = ProjectUserGroupRef.query.filter(and_(ProjectUserGroupRef.project_id == project_id,
                                                    ProjectUserGroupRef.user_group_id == user_group_id)).first()
        if not ref:
            em = 'Invalid user group id {0}'.format(user_group_id)
            logger.info(em)
            return {'ec': 1, 'em': em}
        args = request.get_json()
        if args is None:
            em = 'Invalid request data'
            logger.info(em)
            return {'ec': 1, 'em': em}
        role = args.get('role')
        if role not in PROJECT_ROLES:
            em = 'Invalid role {0}'.format(role)
            logger.info(em)
            return {'ec': 1, 'em': em}
        if role == ref.role:
            return {'ec': 0, 'em': 'success'}
        if not check_project_auth(project_id, g.user, PROJECT_ROLE_MANAGER):
            em = 'No auth to set project {0} user group auth'.format(project_id)
            logger.info(em)
            return {'ec': 1, 'em': em}

        try:
            ProjectUserGroupRef.query.filter(
                and_(ProjectUserGroupRef.project_id == project_id,
                     ProjectUserGroupRef.user_group_id == user_group_id)).update({ProjectUserGroupRef.role: role})
            db_session.commit()
            return {'ec': 0, 'em': 'success'}
        except Exception as e:
            db_session.rollback()
            logger.warn('Unable to set project user group role: %s', e)
            return {'ec': 3, 'em': str(e)}

    def delete(self, project_id, user_group_id):
        project = Project.query.filter(Project.id == project_id).first()
        if not project:
            em = 'Invalid project id {0}'.format(project_id)
            logger.info(em)
            return {'ec': 1, 'em': em}
        if not check_project_auth(project_id, g.user, PROJECT_ROLE_MANAGER):
            em = 'No auth to delete project {0} user group auth'.format(project_id)
            logger.info(em)
            return {'ec': 1, 'em': em}
        ref = ProjectUserGroupRef.query.filter(
            and_(ProjectUserGroupRef.project_id == project_id,
                 ProjectUserGroupRef.user_group_id == user_group_id)).first()
        if not ref:
            return {'ec': 0, 'em': 'success'}
        try:
            db_session.delete(ref)
            db_session.commit()
            return {'ec': 0, 'em': 'success'}
        except Exception as e:
            db_session.rollback()
            logger.warn('Unable to set project user group role: %s', e)
            return {'ec': 3, 'em': str(e)}


# 计费
def charging(resource, used, resource_id, user_id, user_name, project_id, token):
    """
    
    :param resource: eg. redis/rabbitmq/mariadb
    :param used:  eg: 1 container or 2 container
    :param resource_id:  project id
    :param user_id: user's id
    :param user_name:  user's name
    :param project_id:  user's project id
    :param token:  user's token
    :return: 
    """
    try:
        now_time = time.strftime("%Y-%m-%d %H:%M:%s", time.localtime())
        data = {"timestamp": now_time,
                "resources": {"container_num": used,
                              # "memory_mb": "",
                              },
                "resource_id": resource_id,
                "tenant_id": project_id,
                "_context_project_name": user_name,
                "_context_user_name": user_name,
                "resource": resource,
                "user_id": user_id,
                "order_type": 2,
                "end_time": "",
                }
        data = json.dumps(data)
        headers = {'Content-type': 'application/json', 'X-Auth-Token': token.strip()}
        ret = post_http(url=config.charging_ep, data=data, headers=headers)
        if ret.status_code != 200:
            em = "charging error with user id: <{0}>.".format(user_id)
            logger.warn(em)
    except Exception as e:
        em = "charging error with user id: <{0}>. msg: <{1}>".format(user_id, e)
        logger.warn(em)
