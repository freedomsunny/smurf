import datetime
import json
import logging
import re
from collections import OrderedDict

from flask import g, jsonify, request
from flask_restful import Resource, marshal
from sqlalchemy import and_, or_
import smurf.auth as auth

from smurf.db.models import db_session, ServiceTemplate, Service, TemplateCompose, \
    ComposeTemplateRef, ServiceTemplateDepends
from .common import TEMPLATE_FIELDS, TEMPLATE_COMPOSE_FIELDS

logger = logging.getLogger(__name__)


def populate_template(template):
    template_service = json.loads(template.yml)
    template.service = template_service.get('service')
    template.hostname = template_service.get('hostname')
    template.aliases = template_service.get('aliases')
    template.environment = template_service.get('environment')
    depends_rows = db_session.query(ServiceTemplateDepends.template_id_depend).filter(
        ServiceTemplateDepends.template_id == template.id).all()
    depends = [r[0] for r in depends_rows]
    template.depends = depends


class ServiceTemplateListAPI(auth.X_resource):
    DOCKER_CONFIG_KEYS = [
        'image',
        'environment'
    ]

    def get(self, template_id=None):
        """
        method to get ServiceTemplate list
        """
        if not self.result.get("success"):
            return self.result
        if template_id:
            service_templates = ServiceTemplate.query.filter(ServiceTemplate.id == template_id).all()
        else:
            service_templates = ServiceTemplate.query.filter().all()
        for template in service_templates:
            populate_template(template)
        return {
            "servicetemplates": [marshal(service_template, TEMPLATE_FIELDS) for service_template in service_templates]}

    # def post(self, group_id):
    def post(self):
        """        
        method to add a ServiceTemplate
        """
        if not self.result.get("success"):
            return self.result

        args = self.args
        name = args.get("name")
        if (name is None) or (type(name) is not unicode) or len(name.strip()) == 0:
            em = 'Invalid name {0}'.format(name)
            logger.info(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
        name = name.strip()
        description = args.get("description")
        if description and type(description) is not unicode:
            em = 'Invalid description {0}'.format(description)
            logger.info(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
        exist_template = ServiceTemplate.query.filter(ServiceTemplate.name == name).first()
        if exist_template:
            em = 'ServiceTemplate {0} is already exist'.format(name)
            logger.info(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
        service = args.get("service")
        if (service is None) or (type(service) is not unicode) or (not re.match('^[a-zA-Z0-9\._\-]+$', service)):
            em = 'Invalid service {0}'.format(service)
            logger.info(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
        image = args.get("image")
        if (image is None) or (type(image) is not unicode) or len(image.strip()) == 0:
            em = 'Invalid image {0}'.format(image)
            logger.info(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
        hostname = args.get('hostname')
        if (hostname is not None) and (type(hostname) is not unicode):
            em = 'Invalid hostname {0}'.format(hostname)
            logger.info(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
        aliases = args.get('aliases')
        if (aliases is not None) and (type(aliases) is not list):
            em = 'Invalid aliases {0}'.format(aliases)
            logger.info(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
        command = args.get('command')
        if (command is not None) and (type(command) is not unicode):
            em = 'Invalid command {0}'.format(command)
            logger.info(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
        environment = args.get('environment')
        if environment is not None:
            if type(environment) is not dict:
                em = 'Invalid environment {0}'.format(environment)
                logger.info(em)
                return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
            for key in environment:
                if (key is None) or (type(key) is not unicode) or len(key.strip()) == 0:
                    em = 'Invalid environment key {0}'.format(key)
                    logger.info(em)
                    return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
        independent = args.get('independent')
        if (independent is not None) and (type(independent) is not bool):
            em = 'Invalid independent {0}'.format(independent)
            logger.info(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
        depends = args.get('depends')
        if (depends is not None) and (type(depends) is not list):
            em = 'Invalid template depends {0}'.format(depends)
            logger.info(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}

        service_dict = OrderedDict({'service': service})
        service_dict['image'] = image
        if hostname is not None:
            service_dict['hostname'] = hostname
        if aliases is not None:
            for tmp in aliases:
                if tmp == '':
                    aliases.remove(tmp)
            service_dict['aliases'] = aliases
        if command is not None:
            service_dict['command'] = command
        if environment is not None:
            service_dict['environment'] = args['environment']
        service_yml = json.dumps(service_dict)
        # user_id = self.context.get('user_id')
        user_id = None
        service_template = ServiceTemplate(name, description, image, service_yml, user_id, independent)
        try:
            db_session.add(service_template)
            db_session.flush()
            if depends is not None:
                for depend in depends:
                    service_template_depends = ServiceTemplateDepends(service_template.id, depend)
                    db_session.add(service_template_depends)
            db_session.commit()
            logger.info('{0} created'.format(service_template))
            populate_template(service_template)
        except Exception as e:
            logger.warn(e)
            db_session.rollback()
            return {"error": [{"code": 500, "msg": "{0}".format(e)}]}

        return jsonify(servicetemplate=marshal(service_template, TEMPLATE_FIELDS))

    def delete(self, template_id):
        """
        method to delete template

        """
        if not self.result.get("success"):
            return self.result
        exist_template = ServiceTemplate.query.filter(ServiceTemplate.id == template_id).first()
        if not exist_template:
            em = 'Invalid ServiceTemplateGroup id ' + str(template_id)
            logger.info(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
        try:
            ServiceTemplate.query.filter(ServiceTemplate.id == template_id).delete()
            db_session.commit()
        except Exception as e:
            em = 'Invalid delete service template with group_id id: {0} msg: {1} '.format(template_id, e)
            logger.info(em)
            return {"error": [{"code": 401, "msg": "{0}".format(em)}]}
        return {"success": [{"code": 200, "msg": ""}]}


class TemplateComposeListAPI(auth.X_resource):
    def get(self):
        """
        method to get TemplateCompose list
        """
        if not self.result.get("success"):
            return self.result

        composes = TemplateCompose.query.filter(TemplateCompose.removed == None).all()
        if not composes:
            return {"error": [{"code": 400, "msg": ""}]}

        return {"templatecomposes": [marshal(group, TEMPLATE_COMPOSE_FIELDS) for group in composes]}

    def post(self):
        """
        method to add TemplateCompose list
        """
        if not self.result.get("success"):
            return self.result

        name = self.args.get('name')
        description = self.args.get('description')
        environment = self.args.get("environment")
        if environment:
            environment = json.dumps(self.args.get("environment"))
        # check name is it exist
        exist_compose = TemplateCompose.query.filter(TemplateCompose.name == name).first()
        if exist_compose:
            em = "TemplateCompose is already existed. name: <{0}>".format(name)
            logger.info(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}

        compose = TemplateCompose(name, description, environment=environment)
        try:
            db_session.add(compose)
            db_session.commit()
            logger.info('{0} created'.format(compose))
            compose_ret = TemplateCompose.query.filter(TemplateCompose.id == compose.id).first()
            return marshal(compose_ret, TEMPLATE_COMPOSE_FIELDS, 'templatecompose')
        except Exception as e:
            logger.warn(e)
            db_session.rollback()
            return {"error": [{"code": 401, "msg": "{0}".format(e)}]}

    def delete(self, name):
        """
        method to delete TemplateCompose list
        :param name: 
        :return: 
        """
        if not self.result.get("success"):
            return self.result

        compose = TemplateCompose.query.filter(TemplateCompose.name == name).first()
        if not compose:
            em = 'name {0} not found'.format(name)
            logger.info(em)
            return {"error": [{"code": 401, "msg": "{0}".format(em)}]}
        try:
            db_session.delete(compose)
            db_session.commit()
            logger.info('{0} removed'.format(compose))
        except Exception as e:
            logger.warn(e)
            db_session.rollback()
            return {"error": [{"code": 401, "msg": "{0}".format(e)}]}
        return {"success": [{"code": 200, "msg": ""}]}


class TemplateComposeAPI(Resource):

    def get(self, compose_id):
        compose = TemplateCompose.query.filter(
            and_(TemplateCompose.id == compose_id, TemplateCompose.removed == None)).first()
        if compose is None:
            em = 'Invalid TemplateCompose id ' + str(compose_id)
            logger.info(em)
            return {'ec': 1, 'em': em}
        if (not compose.public) and (g.user.id != compose.user_id and g.user.type != 'Admin'):
            em = 'No auth for the TemplateCompose'
            logger.info(em)
            return {'ec': 2, 'em': em}
        for template in compose.templates:
            populate_template(template)
        return marshal(compose, TEMPLATE_COMPOSE_FIELDS, 'templatecompose')

    def delete(self, compose_id):
        compose = TemplateCompose.query.filter(
            and_(TemplateCompose.id == compose_id, TemplateCompose.removed == None)).first()
        if compose is None:
            return {"templatecompose": {"id": compose_id}}
        if (not compose.public and compose.user_id != g.user.id and g.user.type != 'Admin') \
                or (compose.public and g.user.type != 'Admin'):
            em = 'No auth for deleting the TemplateCompose'
            logger.info(em)
            return {'ec': 1, 'em': em}
        try:
            TemplateCompose.query.filter(TemplateCompose.id == compose_id).update(
                {TemplateCompose.removed: datetime.datetime.now()})
            db_session.commit()
            logger.info('{0} removed'.format(compose))
        except Exception as e:
            logger.warn(e)
            db_session.rollback()
            return {'ec': 3, 'em': 'Exception {0}'.format(e)}
        return {"templatecompose": {"id": compose_id}}


class TemplateComposeTemplateListAPI(auth.X_resource):
    def post(self):
        """
        method to add template to template groups
        """
        if not self.result.get("success"):
            return self.result

        template_id = self.args.get('template_id')
        compose_id = self.args.get('compose_id')

        compose = TemplateCompose.query.filter(
            and_(TemplateCompose.id == compose_id, TemplateCompose.removed == None)).first()
        if not compose:
            em = 'Invalid compose id {0}'.format(compose_id)
            logger.info(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}

        if type(template_id) is not int:
            em = 'Invalid template_id {0}, it should be a integer'.format(template_id)
            logger.info(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}

        template = ServiceTemplate.query.filter(ServiceTemplate.id == template_id).first()
        if not template:
            em = 'Invalid template_id {0}'.format(template_id)
            logger.info(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}

        exist_ref = ComposeTemplateRef.query.filter(
            and_(ComposeTemplateRef.compose_id == compose_id, ComposeTemplateRef.template_id == template_id)).first()
        if exist_ref:
            em = 'Template {0} is already added to compose {1}'.format(template_id, compose_id)
            logger.info(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}

        ref = ComposeTemplateRef(compose.id, template_id)
        try:
            db_session.add(ref)
            db_session.commit()
            logger.info('Template {0} added to compose {1}'.format(template_id, compose_id))
            compose_ret = TemplateCompose.query.filter(TemplateCompose.id == compose_id).first()
            return marshal(compose_ret, TEMPLATE_COMPOSE_FIELDS, 'templatecompose')
        except Exception as e:
            logger.warn(e)
            db_session.rollback()
            return {"error": [{"code": 500, "msg": "{0}".format(e)}]}

    def delete(self):

        """
        method to delete ComposeTemplate
        """
        if not self.result.get("success"):
            return self.result

        compose_id = self.args.get('compose_id')
        template_id = self.args.get('template_id')

        compose = TemplateCompose.query.filter(
            and_(TemplateCompose.id == compose_id, TemplateCompose.removed == None)).first()
        if not compose:
            em = 'Invalid compose id {0}'.format(compose_id)
            logger.info(em)
            return {"error": [{"code": 401, "msg": "{0}".format(em)}]}
        ref = ComposeTemplateRef.query.filter(ComposeTemplateRef.compose_id == compose_id,
                                              ComposeTemplateRef.template_id == template_id).first()
        if not ref:
            em = "ComposeTemplate is not exist"
            return {"error": [{"code": 401, "msg": "{0}".format(em)}]}

        try:
            db_session.delete(ref)
            db_session.commit()
            logger.info('Template ref {0} deleted from compose {1}'.format(ref.id, compose_id))
            return {"success": [{"code": 200, "msg": ""}]}
        except Exception as e:
            logger.warn(e)
            db_session.rollback()
            return {"error": [{"code": 500, "msg": ""}]}


