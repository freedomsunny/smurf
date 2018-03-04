import logging
import json
import re

from flask import g, request
from flask_restful import Resource, marshal, fields
from sqlalchemy import and_, func
from compose.project import NoSuchService

from smurf.db.models import db_session, Project, Service, ServiceTemplate, Network, VlanIpAddress, \
    ServiceTemplateDepends
from smurf.bridge import ProjectWrapper
from .project import get_compose_project, setup_project_yml, save_project_yml, populate_project_service, \
    check_service_networks
from .common import SERVICE_FIELDS, PROJECT_ROLE_MANAGER, PROJECT_ROLE_GUEST

logger = logging.getLogger(__name__)


def start_service(project, service):
    # Always regenerate project yml since template may be changed after last up
    project_yml = setup_project_yml(project)
    if project_yml != project.yml:
        Project.query.filter(Project.id == project.id).update({'yml': project_yml})
        db_session.commit()
    save_project_yml(project)

    compose_project = get_compose_project(project)
    project_adapter = ProjectWrapper(compose_project)
    project_adapter.up(service_names=[service.name])
    Project.query.filter(Project.id == project.id).update({Project.state: 'active'})
    db_session.commit()
    return compose_project.name


class ServiceListAPI(Resource):
    def __init__(self):
        pass

    def post(self, project_id):

        project = Project.query.filter(Project.id == project_id).first()
        if project is None:
            em = 'Invalid project id ' + str(project_id)
            logger.info(em)
            return {'ec': 1, 'em': em}
        services = request.get_json()
        if not services:
            em = 'No service provided'
            logger.info(em)
            return {'ec': 1, 'em': em}

        existing_services = Service.query.filter(Service.project_id == project_id).all()
        service_names = [s.name for s in existing_services]
        all_networks = Network.query.filter(Network.removed == None).all()
        if not all_networks:
            allowed_external_nets = []
        else:
            allowed_external_nets = [network.name for network in all_networks
                                     if g.user.type == 'Admin'
                                     or network.public
                                     or (g.user.id in [user.id for user in network.users])
                                     ]

        service_depends = {}
        template_id_depends = []
        template_ids = [s.template_id for s in existing_services]
        for s_name in list(services.keys()):
            template_id = services[s_name].get("template_id")
            template_ids.append(template_id)
            template_depends = ServiceTemplateDepends.query.filter(
                ServiceTemplateDepends.template_id == template_id).all()
            for service_template_depend in template_depends:
                if service_template_depend.template_id_depend not in template_id_depends:
                    template_id_depends.append(service_template_depend.template_id_depend)
                    template_depend = ServiceTemplate.query.filter(
                        ServiceTemplate.id == service_template_depend.template_id_depend).first()
                    service_template_data = json.loads(template_depend.yml)
                    service_depend = {}
                    service_depend["template_id"] = template_depend.id
                    if service_template_data.get("environment"):
                        service_depend["environment"] = service_template_data.get("environment")
                    if service_template_data.get("hostname"):
                        service_depend["hostname"] = service_template_data.get("hostname")
                    service_depend["restart"] = "always"
                    service_depend["networks"] = {"default": {}}
                    name = service_template_data.get("service")
                    service_depends[name] = service_depend
        for s_name in list(service_depends.keys()):
            template_id = service_depends[s_name].get("template_id")
            if template_id not in template_ids:
                services[s_name] = service_depends[s_name]

        for s_name in list(services.keys()):
            if (s_name is None) or (type(s_name) is not unicode) or (not re.match('^[a-zA-Z0-9\._\-]+$', s_name)):
                em = 'Invalid service name {0}'.format(s_name)
                logger.info(em)
                return {'ec': 1, 'em': em}
            if s_name in service_names:
                em = 'Duplicated service name {0}'.format(s_name)
                logger.info(em)
                return {'ec': 1, 'em': em}
            service_names.append(s_name)
            template_id = services[s_name].get("template_id")
            template = ServiceTemplate.query.filter(ServiceTemplate.id == template_id).first()
            if not template:
                em = 'Invalid template id {0}'.format(template_id)
                logger.info(em)
                return {'ec': 1, 'em': em}
            networks = services[s_name].get("networks")
            if networks:
                for n_name in networks:
                    if n_name != "default":
                        network = networks.get(n_name)
                        ipaddress = network.get("ipv4_address")
                        network_db = Network.query.filter(Network.name == n_name).first()
                        if ipaddress == '':
                            ipaddress_db = VlanIpAddress.query.filter(and_(VlanIpAddress.network_id == network_db.id,
                                                                           VlanIpAddress.state == 'free')).order_by(
                                func.rand()).first()
                            if ipaddress_db:
                                network["ipv4_address"] = ipaddress_db.ip_address
                        else:
                            ipaddress_db = VlanIpAddress.query.filter(
                                and_(VlanIpAddress.network_id == network_db.id, VlanIpAddress.state == 'allocated',
                                     VlanIpAddress.ip_address == ipaddress)).first()
                            if ipaddress_db:
                                em = 'IP address {0} has been used'.format(ipaddress_db.ip_address)
                                logger.info(em)
                                return {'ec': 1, 'em': em}
                            ipaddress_db = VlanIpAddress.query.filter(
                                and_(VlanIpAddress.network_id == network_db.id, VlanIpAddress.state == 'free',
                                     VlanIpAddress.ip_address == ipaddress)).first()
                        if ipaddress_db:
                            VlanIpAddress.query.filter(VlanIpAddress.id == ipaddress_db.id).update(
                                {VlanIpAddress.user_id: g.user.id, VlanIpAddress.state: 'allocated'})
                em = check_service_networks(s_name, networks, allowed_external_nets)
                if em != '':
                    logger.info(em)
                    return {'ec': 1, 'em': em}

                # Change service name
                if VLAN_CON_CANT_USE_FULL_NAME in networks:
                    s_new_name = s_name.split('.')[0]
                    if s_new_name != s_name:
                        if s_new_name in service_names:
                            em = "Unable to rename service {0} to {1}, duplicated service".format(s_name, s_new_name)
                            logger.info(em)
                            return {'ec': 1, 'em': em}
                        services[s_new_name] = services.pop(s_name)
                        logger.info("Service name %s changed to %s", s_name, s_new_name)
            else:
                services[s_name]["networks"] = {"default": {}}

            # Set default network aliases
            if 'default' in networks:
                default_network = networks.get("default")
                if default_network is None:
                    default_network = {}
                    networks["default"] = default_network
                service_template_data = json.loads(template.yml)
                service_template_service = service_template_data.get("service")
                service_template_aliases = service_template_data.get("aliases")
                if service_template_aliases is None:
                    service_template_aliases = [service_template_service]
                else:
                    service_template_aliases.append(service_template_service)
                logger.info(service_template_aliases)
                default_network['aliases'] = service_template_aliases

        try:
            for s_name in services:
                service = services[s_name]
                template_id = service['template_id']
                data = {}
                if service.get("hostname"):
                    data["hostname"] = service.get("hostname")
                if service.get("environment"):
                    data["environment"] = service.get("environment")
                if service.get("command"):
                    data["command"] = service.get("command")
                data["restart"] = "always"
                if service.get("networks"):
                    data["networks"] = service.get("networks")
                new_service = Service(s_name, project.id, template_id, json.dumps(data))
                db_session.add(new_service)
                db_session.flush()
                networks = service.get("networks")
                for n_name in networks:
                    if n_name != "default":
                        network = networks.get(n_name)
                        ipaddress = network.get("ipv4_address")
                        if ipaddress != '':
                            VlanIpAddress.query.filter(VlanIpAddress.ip_address == ipaddress).update(
                                {VlanIpAddress.service_id: new_service.id})
            project_yml = setup_project_yml(project)
            Project.query.filter(Project.id == project.id).update({Project.yml: project_yml})
            db_session.commit()
            save_project_yml(project)
            logger.info('%s created', project)
            return {'ec': 0, 'em': 'success'}
        except Exception as e:
            db_session.rollback()
            logger.warn("Unable to add services: %s", e)
            return {'ec': 3, 'em': str(e)}


class ServiceAPI(Resource):
    def __init__(self):
        pass

    def get(self, project_id, service_id):

        project = Project.query.filter(Project.id == project_id).first()
        if project is None:
            em = 'Invalid project id ' + str(project_id)
            logger.info(em)
            return {'ec': 1, 'em': em}
        service = Service.query.filter(and_(Service.project_id == project_id, Service.id == service_id)).first()
        if service is None:
            em = 'Invalid service id ' + str(service_id)
            logger.info(em)
            return {'ec': 1, 'em': em}
        populate_project_service(service)
        service_fields = SERVICE_FIELDS
        service_fields["project_id"] = fields.Integer
        return marshal(service, service_fields, envelope="service")

    def put(self, project_id, service_id):

        project = Project.query.filter(Project.id == project_id).first()
        if project is None:
            em = 'Invalid project id ' + str(project_id)
            logger.info(em)
            return {'ec': 1, 'em': em}
        service = Service.query.filter(and_(Service.project_id == project_id, Service.id == service_id)).first()
        if service is None:
            em = 'Invalid service id ' + str(service_id)
            logger.info(em)
            return {'ec': 1, 'em': em}

        args = request.get_json()
        template_id = args.get('template_id')
        template = ServiceTemplate.query.filter(ServiceTemplate.id == template_id).first()
        if not template:
            em = 'Invalid template id {0}'.format(template_id)
            logger.info(em)
            return {'ec': 1, 'em': em}
        data = {'name': service.name}
        if args.get("hostname"):
            data["hostname"] = args.get("hostname")
        if args.get("environment"):
            data["environment"] = args.get("environment")
        if args.get("command"):
            data["command"] = args.get("command")
        data["restart"] = "always"
        s_name = service.name
        s_new_name = service.name
        networks = args.get("networks")
        if networks:
            for n_name in networks:
                if n_name != "default":
                    network = networks.get(n_name)
                    ipaddress_new = network.get("ipv4_address")
                    network_db = Network.query.filter(Network.name == n_name).first()
                    ipaddress_db = VlanIpAddress.query.filter(
                        and_(VlanIpAddress.network_id == network_db.id, VlanIpAddress.state == 'allocated',
                             VlanIpAddress.service_id == service_id)).first()
                    if ipaddress_db:
                        ipaddress_old = ipaddress_db.ip_address
                    else:
                        ipaddress_old = ''
                    if ipaddress_new == '' and ipaddress_old == '':
                        ipaddress_db = VlanIpAddress.query.filter(
                            and_(VlanIpAddress.network_id == network_db.id, VlanIpAddress.state == 'free')).order_by(
                            func.rand()).first()
                        network["ipv4_address"] = ipaddress_db.ip_address
                        VlanIpAddress.query.filter(VlanIpAddress.ip_address == ipaddress_db.ip_address).update(
                            {VlanIpAddress.service_id: service_id, VlanIpAddress.user_id: g.user.id,
                             VlanIpAddress.state: 'allocated'})
                    elif ipaddress_new == '' and ipaddress_old != '':
                        network["ipv4_address"] = ipaddress_old
                    elif ipaddress_new != ipaddress_old:
                        ipaddress_db = VlanIpAddress.query.filter(
                            and_(VlanIpAddress.network_id == network_db.id, VlanIpAddress.state == 'allocated',
                                 VlanIpAddress.ip_address == ipaddress_new)).first()
                        if ipaddress_db:
                            em = 'IP address {0} has been used'.format(ipaddress_db.ip_address)
                            logger.info(em)
                            return {'ec': 1, 'em': em}
                        else:
                            VlanIpAddress.query.filter(VlanIpAddress.ip_address == ipaddress_new).update(
                                {VlanIpAddress.service_id: service_id, VlanIpAddress.user_id: g.user.id,
                                 VlanIpAddress.state: 'allocated'})
                            VlanIpAddress.query.filter(VlanIpAddress.ip_address == ipaddress_old).update(
                                {VlanIpAddress.service_id: None, VlanIpAddress.user_id: None,
                                 VlanIpAddress.state: 'free'})
            all_networks = Network.query.filter(Network.removed == None).all()
            if not all_networks:
                allowed_external_nets = []
            else:
                allowed_external_nets = [network.name for network in all_networks
                                         if g.user.type == 'Admin'
                                         or network.public
                                         or (g.user.id in [user.id for user in network.users])
                                         ]
            em = check_service_networks(service.name, networks, allowed_external_nets)
            if em != '':
                logger.info(em)
                return {'ec': 1, 'em': em}

            service_name_rows = db_session.query(Service.name).filter(Service.project_id == service.project_id).all()
            service_names = [r[0] for r in service_name_rows]

            # Change service name
            if VLAN_CON_CANT_USE_FULL_NAME in networks:
                s_new_name = s_name.split('.')[0]
                if s_new_name != s_name:
                    if s_new_name in service_names:
                        em = "Unable to rename service {0} to {1}, duplicated service".format(s_name, s_new_name)
                        logger.info(em)
                        return {'ec': 1, 'em': em}
                    logger.info("Service name %s changed to %s", s_name, s_new_name)
        else:
            networks = {"default": {}}

        # Set default network aliases
        if 'default' in networks:
            default_network = networks.get("default")
            if default_network is None:
                default_network = {}
                networks["default"] = default_network
            service_template_data = json.loads(template.yml)
            service_template_service = service_template_data.get("service")
            service_template_aliases = service_template_data.get("aliases")
            if service_template_aliases is None:
                service_template_aliases = [service_template_service]
            else:
                service_template_aliases.append(service_template_service)
            logger.info(service_template_aliases)
            default_network['aliases'] = service_template_aliases

        data["networks"] = networks

        # Remove containers before we change the service.
        restart = False
        if project.state != 'created':
            try:
                compose_project = get_compose_project(project)
                containers = compose_project.containers(service_names=[service.name], stopped=True)
                for container in containers:
                    if container.is_running:
                        restart = True
                    container.remove(force=True)
            except NoSuchService:
                pass
            except Exception as e:
                logger.warn(type(e))
                em = 'Unable to remove containers of service {0}: {1}'.format(service.name, e)
                logger.warn(em)
                return {'ec': 2, 'em': em}

        try:
            Service.query.filter(Service.id == service_id).update({
                Service.name: s_new_name,
                Service.template_id: template_id,
                Service.data: json.dumps(data)
            })
            db_session.commit()
            logger.info('Service %s updated, %s', service.name, project)
            if restart:
                start_service(project, service)
            return {'ec': 0, 'em': 'success'}
        except Exception as e:
            em = 'Unable to update service: {0}'.format(e)
            db_session.rollback()
            logger.warn(em)
            return {'ec': 2, 'em': em}

    def delete(self, project_id, service_id):

        project = Project.query.filter(Project.id == project_id).first()
        if project is None:
            em = 'Invalid project id ' + str(project_id)
            logger.info(em)
            return {'ec': 1, 'em': em}
        service = Service.query.filter(and_(Service.project_id == project_id, Service.id == service_id)).first()
        if service is None:
            em = 'Invalid service id ' + str(service_id)
            logger.info(em)
            return {'ec': 1, 'em': em}
        existing_services = Service.query.filter(Service.project_id == project_id).all()
        if len(existing_services) == 1:
            em = 'Unable to remove the only one service {0}. Please delete the project instead'.format(service_id)
            logger.info(em)
            return {'ec': 1, 'em': em}

        if project.state != 'created':
            try:
                compose_project = get_compose_project(project)
                containers = compose_project.containers(service_names=[service.name], stopped=True)
                for container in containers:
                    container.remove(v=True, force=True)
            except Exception as e:
                em = 'Unable to remove containers of service {0}: {1}'.format(service.name, e)
                logger.warn(em)
                return {'ec': 2, 'em': em}

        try:
            VlanIpAddress.query.filter(VlanIpAddress.service_id == service.id).update(
                {VlanIpAddress.service_id: None, VlanIpAddress.user_id: None, VlanIpAddress.state: 'free'})
            db_session.delete(service)
            db_session.flush()
            project_yml = setup_project_yml(project)
            Project.query.filter(Project.id == project.id).update({'yml': project_yml})
            db_session.commit()
            logger.info('{0} deleted'.format(service))
            save_project_yml(project)
            return {'ec': 0, 'em': 'success'}
        except Exception as e:
            logger.warn(e)
            db_session.rollback()
            return {'ec': 3, 'em': 'Exception {0}'.format(e)}


class ServiceActionAPI(Resource):
    def __init__(self):
        pass

    def post(self, project_id, service_id, action):

        project = Project.query.filter(Project.id == project_id).first()
        if project is None:
            em = 'Invalid project id ' + str(project_id)
            logger.info(em)
            return {'ec': 1, 'em': em}
        service = Service.query.filter(and_(Service.project_id == project_id, Service.id == service_id)).first()
        if service is None:
            em = 'Invalid service id ' + str(service_id)
            logger.info(em)
            return {'ec': 1, 'em': em}
        if action == "start":
            return self.start(project, service)
        if action == "stop":
            return self.stop(project, service)
        return {"ec": 2, "em": "unsported action"}

    def start(self, project, service):
        try:
            project_name = start_service(project, service)
            logger.info("Service %s started, compose project %s", service.name, project_name)
            return {'ec': 0, 'em': 'success'}
        except Exception as e:
            db_session.rollback()
            logger.warn(str(e))
            return {'ec': 1, 'em': str(e)}

    def stop(self, project, service):
        try:
            compose_project = get_compose_project(project)
            compose_project.stop(service_names=[service.name])
            logger.info("Service %s stopped, compose project %s", service.name, compose_project.name)
            return {'ec': 0, 'em': 'success'}
        except Exception as e:
            db_session.rollback()
            logger.warn(str(e))
            return {'ec': 1, 'em': str(e)}
