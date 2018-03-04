'''
create app instance
'''
import json
import logging
import logging.config
import os
from datetime import timedelta
from flask import Flask, g, session, jsonify
from flask_restful import Api
from flask_cors import *
from celery import Celery

from smurf.db.models import engine, db_session, User
from smurf.resources.container import ContainerAPI, ContainerActionAPI
from smurf.resources.network import NetworkListAPI, GetPortAbout, ConfigureSdnSwitch, ConfigureL2Switch
from smurf.resources.project import ProjectActionAPI, ProjectListAPI, ProjectAPI, restore_project_ymls, \
    ProjectUserListAPI, ProjectUserGroupListAPI, ProjectUserGroupAPI
from smurf.resources.service import ServiceListAPI, ServiceAPI, ServiceActionAPI
from smurf.resources.template import ServiceTemplateListAPI, TemplateComposeAPI, TemplateComposeListAPI, \
    TemplateComposeTemplateListAPI
from smurf.resources.registry import ImageListAPI


def setup_logging(
        default_path='logging.json',
        default_level=logging.DEBUG,
        env_key='LOG_CFG'):
    """
    Setup logging configuration
    """
    path = default_path
    value = os.getenv(env_key, None)
    if value:
        path = value
    if os.path.exists(path):
        with open(path, 'rt') as f:
            config = json.load(f)
            logging.config.dictConfig(config)
    else:
        logging.basicConfig(level=default_level)


setup_logging()

logger = logging.getLogger(__name__)

# Restore project ymls only if database has been setup
# if engine.dialect.has_table(engine, User.__tablename__):
#     restore_project_ymls()

app = Flask(__name__)
app.secret_key = '9b7f2055-dbf0-4b55-89de-8a440afa4a55'
CORS(app, supports_credentials=True)


# Set session timeout
# app.permanent_session_lifetime = timedelta(minutes=600)


# @app.teardown_appcontext
# def shutdown_session(exception=None):
#     db_session.remove()

@app.teardown_request
def shutdown_session(exception=None):
    db_session.remove()


@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.filter(User.id == user_id).first()
        g.user = user


@app.route("/api/login", methods=['POST'])
def login():
    pass


@app.route("/api/logout")
def logout():
    session.pop('user_id', None)
    g.user = None
    return jsonify(ec=0, em='Logout Success')


api = Api(app)

api.add_resource(ServiceTemplateListAPI,
                 "/api/v1.0/servicetemplate/",
                 "/api/v1.0/servicetemplate/<int:template_id>",
                 endpoint="ep_servicetemplates")
api.add_resource(TemplateComposeListAPI,
                 "/api/v1.0/templatecomposes",
                 "/api/v1.0/templatecomposes/<name>",
                 endpoint="ep_templatecomposes")
api.add_resource(TemplateComposeAPI,
                 "/api/v1.0/templatecomposes/<int:compose_id>",
                 endpoint="ep_templatecompose")
api.add_resource(TemplateComposeTemplateListAPI,
                 "/api/v1.0/templatecomposeslist",
                 endpoint="ep_templatecomposetemplates")
api.add_resource(ProjectListAPI,
                 "/api/v1.0/projects",
                 endpoint="ep_projects")
api.add_resource(ProjectAPI,
                 "/api/v1.0/projects/<int:project_id>",
                 endpoint="ep_project")
api.add_resource(ProjectActionAPI,
                 "/api/v1.0/projects/<int:project_id>/<action>",
                 endpoint="ep_projectaction")
api.add_resource(ServiceListAPI,
                 "/api/v1.0/projects/<int:project_id>/services",
                 endpoint="ep_services")
api.add_resource(ServiceAPI,
                 "/api/v1.0/projects/<int:project_id>/services/<int:service_id>",
                 endpoint="ep_service")
api.add_resource(ServiceActionAPI,
                 "/api/v1.0/projects/<int:project_id>/services/<int:service_id>/<action>",
                 endpoint="ep_serviceaction")
api.add_resource(ContainerAPI,
                 "/api/v1.0/projects/<int:project_id>/services/<int:service_id>/containers/<container_id>",
                 endpoint="ep_container")
api.add_resource(ContainerActionAPI,
                 "/api/v1.0/projects/<int:project_id>/services/<int:service_id>/containers/<container_id>/<action>",
                 endpoint="ep_containeraction")
api.add_resource(ProjectUserListAPI,
                 "/api/v1.0/projects/<int:project_id>/users",
                 endpoint="ep_projectusers")
api.add_resource(ProjectUserGroupListAPI,
                 "/api/v1.0/projects/<int:project_id>/usergroups",
                 endpoint="ep_projectusergroups")
api.add_resource(ProjectUserGroupAPI,
                 "/api/v1.0/projects/<int:project_id>/usergroups/<int:user_group_id>",
                 endpoint="ep_projectusergroup")
api.add_resource(NetworkListAPI,
                 "/api/v1.0/networks",
                 "/api/v1.0/networks/<name>",
                 endpoint="ep_networks")
api.add_resource(ImageListAPI,
                 "/api/v1.0/images",
                 endpoint="ep_images")
api.add_resource(ConfigureSdnSwitch,
                 "/api/v1.0/switch/sdn",
                 endpoint="ep_sdn")
api.add_resource(ConfigureL2Switch,
                 "/api/v1.0/switch/l2switch",
                 endpoint="ep_l2")
