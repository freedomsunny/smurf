from flask_restful import Resource

from smurf.docker_registry.query import get_query
import smurf.config as config


registry_query = get_query(config.DOCKER_REGISTRY)


class ImageListAPI(Resource):

    def get(self):
        tag_names = registry_query.get_tag_names()
        return {config.DOCKER_REGISTRY: tag_names}
