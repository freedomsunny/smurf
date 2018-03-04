# -*- coding:utf-8 -*-
import redis
import cPickle
import smurf.config as config


class Backend(object):
    def __init__(self):
        cached_backend = config.cached_backend
        _conn = cached_backend.split("//")[1]
        if '@' in _conn:
            passwd, host_port = _conn.split('@')
        else:
            passwd = None
            host_port = _conn
        if passwd:
            passwd = passwd[1:]
        host, db_p = host_port.split(':')
        port, db = db_p.split('/')
        self.conn = redis.StrictRedis(host=host, port=port, db=db, password=passwd)

    def get(self, id, default=None):
        """
        Return object with id 
        """
        try:
            ret = self.conn.get(id)
            if ret:
                ret = cPickle.loads(ret)["msg"]
        except:
            ret = default
        return ret

    def set(self, id, user_msg, timeout=config.cache_timeout):
        """
        Set obj into redis-server.
        Expire 3600 sec
        """
        try:
            if user_msg:
                msg = cPickle.dumps({"msg": user_msg})
                self.conn.set(id, msg)
                self.conn.expire(id, timeout)
                return True
        except:
            self.conn.delete(id)
            return False

    def delete(self, id):
        try:
            self.conn.delete(id)
        except:
            pass

    def get_user_roles(self, id):
        cache_id = '%s_%s' % ('roles', id)
        if not self.get(id):
            return []
        roles = self.get(cache_id)
        if not roles:
            if 'roles' in self.get(id):
                roles = [role['name'] for role in self.get(id)['roles']]
                self.set(cache_id, roles)
        return roles

    def keys(self, key):
        return self.conn.keys(key)
