import logging
from flask import g, request, jsonify
from flask_restful import Resource, fields, marshal
from sqlalchemy import and_

from smurf.db.models import Project, db_session
from smurf.resources.project import get_compose_project
from smurf.bridge import get_container_from_id
import smurf.auth as auth

logger = logging.getLogger(__name__)

CONTAINER_FIELDS = {
    'id': fields.String,
    'short_id': fields.String,
    'human_readable_command': fields.String,
    'name': fields.String,
    'name_without_project': fields.String,
    'number': fields.String,
    'ports': fields.Raw,
    'ip': fields.String,
    'hostname': fields.String,
    'labels': fields.Raw,
    'image': fields.String,
    'environment': fields.Raw,
    'service': fields.String,
    'started_at': fields.String,
    'status': fields.String,
    'volumes': fields.Raw,
    'networks': fields.Raw
}


class ContainerAPI(auth.X_resource):

    def get(self, project_id, service_id, container_id):
        "mehtod get Container info"
        if not self.result.get("success"):
            return self.result

        user_name = self.context.get("user_name")
        project = Project.query.filter(Project.id == project_id).first()
        if project is None:
            em = 'Invalid project {0}'.format(project_id)
            logger.info(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}

        compose_project = get_compose_project(project, user_name)
        container = get_container_from_id(compose_project.client, container_id)
        container_resp = self._make_container_resp(container)

        return marshal(container_resp, CONTAINER_FIELDS, envelope='container')

    def _make_container_resp(self, container):
        ip = container.get('NetworkSettings.IPAddress')
        if not ip:
            # use external network ip
            networks = container.get('NetworkSettings.Networks')
            ip = networks.items()[0][1].get('IPAddress')
            if len(networks) > 1:
                defualt_net_name = container.labels.get('com.docker.compose.project') + '_default'
                for net in networks:
                    if net != defualt_net_name:
                        ip = networks[net].get('IPAddress')
                        break

        container_resp = {
            'id': container.id,
            'short_id': container.short_id,
            'human_readable_command': container.human_readable_command,
            'name': container.name,
            'name_without_project': container.name_without_project,
            'number': container.number,
            'ports': container.ports,
            'ip': ip,
            'hostname': container.get('Config.Hostname'),
            'labels': container.labels,
            'log_config': container.log_config,
            'image': container.get('Config.Image'),
            'environment': container.environment,
            'service': container.service,
            'started_at': container.get('State.StartedAt'),
            'status': container.get('State.Status'),
            'volumes': container.get('Config.Volumes'),
            'networks': container.get('NetworkSettings.Networks')
        }
        return container_resp


class ContainerActionAPI(auth.X_resource):

    def post(self, project_id, service_id, container_id, action):
        if not self.result.get("success"):
            return self.result

        user_name = self.context.get("user_name")
        if action not in ['start', 'stop', 'restart', 'rm', 'exec', 'logs']:
            em = "invalid action {0}".format(action)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
        success = {"success": [{"code": 200, "msg": ""}]}
        project = Project.query.filter(Project.id == project_id).first()
        if project is None:
            em = 'Invalid project id {0}'.format(project_id)
            logger.info(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}

        try:
            compose_project = get_compose_project(project, user_name)
            container = get_container_from_id(compose_project.client, container_id)
        except Exception as e:
            em = "Unable to get container {0}: {1}".format(container_id, e)
            logger.warn(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
        if not container:
            em = 'Invalid container id {0}'.format(container_id)
            logger.info(em)
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}

        if action == "start":
            try:
                container.start()
                self.update_project_state(project, compose_project)
                logger.info("Container %s started", container_id)
            except Exception as e:
                logger.warn(str(e))
                return {"error": [{"code": 400, "msg": "{0}".format(e)}]}
            return success
        elif action == "stop":
            try:
                container.stop()
                self.update_project_state(project, compose_project)
                logger.info("Container %s stopped", container_id)
            except Exception as e:
                logger.warn(str(e))
                return {"error": [{"code": 400, "msg": "{0}".format(e)}]}
            return success
        elif action == "restart":
            try:
                container.restart()
                logger.info("Container %s restarted", container_id)
            except Exception as e:
                logger.warn(str(e))
                return {'ec': 3, 'em': str(e)}
            return success
        elif action == "logs":
            limit = self.args.get('limit', 200)
            since = None
            if 'since' in self.args:
                since = int(self.args.get('since'))
            try:
                lines = container.logs(timestamps=True, tail=limit, since=since).split('\r\n')
                logger.info('lines count: ' + str(len(lines)))
                return jsonify(logs=lines)
            except Exception as e:
                logger.warn(str(e))
                return {"error": [{"code": 400, "msg": "{0}".format(e)}]}
        elif action == "rm":
            try:
                container.remove(v=True, force=True)
                self.update_project_state(project, compose_project)
                logger.info("Container %s removed", container_id)
            except Exception as e:
                logger.warn(str(e))
                return {"error": [{"code": 400, "msg": "{0}".format(e)}]}
            return success
        elif action == "exec":
            command = self.args.get('Cmd')
            if not command:
                em = "Invalid Cmd"
                logger.info(em)
                return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
            return self.exec_command(container, command)
        return {"error": [{"code": 400, "msg": "unsported action"}]}

    def exec_command(self, container, command):
            """
            containers/<uuid>/?action=exec
            data:
            {
              "Cmd":["mkdir", "/tmp/1"]
            }
            only support sync cmds
            """
            if not self.result.get("success"):
                return self.result

            create_exec_options = {
                "tty": False,
                "stdin": False,
            }
            logger.info('Exec container {0}: {1}'.format(container.short_id, command))
            try:
                exec_id = container.create_exec(command, **create_exec_options)
                container.start_exec(exec_id, detach=False, tty=False)
                exec_info = container.client.exec_inspect(exec_id)
                logger.info('Exec ExitCode {0}'.format(exec_info['ExitCode']))
                return {"success": [{"code": 200, "msg": "{0}".format(exec_info['ExitCode'])}]}
            except Exception as e:
                em = "Unable to exec in container {0}: {1}".format(container.id, e)
                logger.warn(em)
                return {"error": [{"code": 400, "msg": "{0}".format(e)}]}

    def update_project_state(self, project, compose_project):
        containers = compose_project.containers()
        if containers:
            real_state = 'active'
        else:
            real_state = 'inactive'
        if real_state != project.state:
            Project.query.filter(Project.id == project.id).update({Project.state: real_state})
            db_session.commit()
