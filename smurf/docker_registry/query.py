import logging
import json
import os
import threading
from time import sleep

from requests.auth import AuthBase

from .client import DockerRegistryClient


DOCKER_CONFIG_FILE = os.path.expanduser('~/.docker/config.json')


def _str_or_list(value):
    if not value:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


log = logging.getLogger(__name__)


class DockerRegistryQuery(object):
    def __init__(self, client):
        self._client = client
        self._cache = {}
        self._initialized = False
        self._refresh_interval = 300   # 5 minutes
        self.auto_refresh_started = False

    @property
    def client(self):
        return self._client

    def refresh(self):
        log.info("Initializing cache.")
        if self._initialized:
            log.info("Clearing.")
            self._cache.clear()
        repos = self._client.get_catalog().json()['repositories']
        log.info("Found %s repositories.", len(repos))
        for repo in repos:
            log.info("Checking respository '%s'.", repo)
            tags = self._client.get_tags(repo).json()['tags']
            self._cache[repo] = tags
        log.info("Cache init completed.")
        self._initialized = True
        self._start_auto_refresh()

    def _start_auto_refresh(self):
        if self.auto_refresh_started:
            return
        self.auto_refresh_started = True
        self.refresh_thread = threading.Thread(target=self._auto_refresh)
        self.refresh_thread.setDaemon(True)
        self.refresh_thread.start()

    def _auto_refresh(self):
        while True:
            sleep(self._refresh_interval)
            try:
                self.refresh()
            except:
                continue

    def get_repo_names(self):
        """
        Returns a sorted list of available repository names.

        :return: Repository name list.
        :rtype: list[str]
        """
        if not self._initialized:
            self.refresh()
        return self._cache.keys()

    def get_tag_names(self, repos=None):
        """
        Returns a sorted list of available tags, optionally filtered by a set of repository names.

        :param repos: Optional repository name or list names to limit the output.
        :type repos: str | list[str] | tuple[str] | NoneType
        :return: List with tuples of repositories and tags.
        :rtype: list[(str, str)]
        """
        if not self._initialized:
            self.refresh()
        if repos:
            repo_list = _str_or_list(repos)
            return {repo: self._cache[repo] for repo in repo_list}
        else:
            return self._cache

    @property
    def cache(self):
        """
        Returns the cache instance for queries.

        :rtype: Lookup cache for repositories, tags, and digests.
        :rtype: docker_registry_util.cache.ImageDigestCache
        """
        return self._cache

    @property
    def client(self):
        """
        Returns the client instance used for cache updates.

        :return: Docker Registry API client.
        :rtype: docker_registry_util.client.DockerRegistryClient
        """
        return self._client

    def load(self, file):
        """
        Loads a previous state of a cache from a JSON file or file-like object.

        :param file: JSON file.
        """
        self._cache = json.load(file)
        self._initialized = True

    def loads(self, s):
        """
        Loads a previous state of a cache from a JSON string.

        :param s: JSON-formatted string.
        :type s: str
        """
        self._cache = json.loads(s)
        self._initialized = True

    def dump(self, file):
        """
        Saves the current state of the image cache to a file (or file-like object) in JSON format.

        :param file: Output file.
        """
        self._cache.dump(file)

    def dumps(self):
        """
        Returns the current state of the image cache as a string in JSON format.

        :return: str
        """
        return self._cache.dumps()


class HTTPBase64Auth(AuthBase):
    """
    Similar to HTTPBasicAuth, but handles the base64 encoded string directly instead of dividing it into user name
    and password.
    """
    def __init__(self, auth):
        self.auth = auth

    def __eq__(self, other):
        return self.auth == getattr(other, 'auth', None)

    def __ne__(self, other):
        return not self == other

    def __call__(self, r):
        r.headers['Authorization'] = 'Basic {0}'.format(self.auth)
        return r


def _get_auth_config(registry):
    try:
        with open(DOCKER_CONFIG_FILE) as config_file:
            config_data = json.load(config_file)
    except IOError:
        return None
    auth_data = config_data.get('auths')
    if not auth_data:
        return None
    registry_data = auth_data.get(registry)
    if not registry_data:
        return None
    return registry_data.get('auth')


def get_query(registry):
    kwargs = {}
    if os.path.isfile(DOCKER_CONFIG_FILE):
        config_auth = _get_auth_config(registry)
        if config_auth:
            kwargs['auth'] = HTTPBase64Auth(config_auth)
    if registry.startswith('http'):
        base_url = registry
    else:
        base_url = 'http://{0}'.format(registry)
    client = DockerRegistryClient(base_url, **kwargs)
    query = DockerRegistryQuery(client)
    return query
