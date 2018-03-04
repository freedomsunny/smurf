import operator

from compose import parallel
from compose.container import Container
from compose.cli.command import get_project as compose_get_project, get_config_path_from_options
from compose.config.environment import Environment
from compose.const import DEFAULT_TIMEOUT
from compose.project import warn_for_swarm_mode
from compose.service import BuildAction
from compose.service import ConvergenceStrategy

import smurf.config as config


def get_project(path, project_name=None):
    """
    get docker project given file path
    """
    environment = Environment.from_env_file(path)
    config_path = get_config_path_from_options(path, dict(), environment)
    project = compose_get_project(path, config_path, project_name=project_name,
                                  host='{0}:{1}'.format(config.swarm_scheduling_host, config.swarm_scheduling_port))
    return project


def get_container_from_id(client, container_id):
    """
    return the docker container from a given id
    """
    return Container.from_id(client, container_id)


class ProjectWrapper(object):
    """
    Wrap compose project actions to return more detailed errors
    """

    def __init__(self, project):
        self.project = project

    def up(self,
           service_names=None,
           start_deps=True,
           strategy=ConvergenceStrategy.changed,
           do_build=BuildAction.none,
           timeout=DEFAULT_TIMEOUT,
           detached=False,
           remove_orphans=False):

        warn_for_swarm_mode(self.project.client)

        self.project.initialize()
        self.project.find_orphan_containers(remove_orphans)

        services = self.project.get_services_without_duplicate(
            service_names,
            include_deps=start_deps)

        for svc in services:
            svc.ensure_image_exists(do_build=do_build)
        plans = self.project._get_convergence_plans(services, strategy)

        def do(service):
            return service.execute_convergence_plan(
                plans[service.name],
                timeout=timeout,
                detached=detached
            )

        def get_deps(service):
            return {self.project.get_service(dep) for dep in service.get_dependency_names()}

        results, errors = parallel.parallel_execute(
            services,
            do,
            operator.attrgetter('name'),
            None,
            get_deps
        )
        if errors:
            raise ProjectError(
                'Encountered errors while bringing up the project.', errors
            )

        return [
            container
            for svc_containers in results
            if svc_containers is not None
            for container in svc_containers
        ]


class ProjectError(Exception):
    def __init__(self, msg, errors=None):
        self.msg = msg
        self.errors = errors

    def __str__(self):
        if self.errors:
            return "{0}\n {1}".format(self.msg, '\n'.join(['{0}: {1}'.format(service, error) for service, error in self.errors.items()]))
        else:
            return self.msg
