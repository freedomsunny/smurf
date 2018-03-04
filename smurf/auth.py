import flask
import requests
from flask_restful import Resource
import smurf.config as config


class X_resource(Resource):
    def __init__(self):
        super(X_resource, self).__init__()
        self.token = flask.request.headers.get("X-Auth-Token")
        self.context = {}
        self.result = self._auth(self.token)
        self.args = flask.request.get_json()

    def _auth(self, token):
        """
        Auth user by keystone token
        """
        if not token:
            """Reject the request"""
            em = "Authentication failed no token found"
            return {"error": [{"code": 400, "msg": "{0}".format(em)}]}
        return self.get_usermsg_from_keystone(token)

    def _auth_by_token(self, token):
        """
        requires_auth annotation
        """
        url = 'http://{0}:{1}/v2.0/tokens'.format(config.controler_host, config.keystone_auth_port)
        data = '{"auth": {"token": {"id": "%s"}}}' % str(token)
        ret = requests.post(url=url, data=data).json()
        for k, v in ret.iteritems():
            if k == "error":
                em = "Authentication success"
                return {"error": [{"code": 401, "msg": "{0}".format(em)}]}
            else:
                em = "Authentication failed"
                return {"success": [{"code": 200, "msg": "{0}".format(em), "data": v}]}

    def get_usermsg_from_keystone(self, token):
        """
        Return object from keystone by token
        """
        try:
            headers = {'X-Auth-Token': token, 'X-Subject-Token': token, 'Content-type': 'application/json'}
            token_info = requests.get(url=config.keystone_ep + '/auth/tokens', headers=headers).json()['token']
            self.context = {'user_name': token_info.get('user').get("name"),
                            'roles': [role for role in token_info['roles'] if role],
                            'project': token_info['project'],
                            'admin': 'admin' in [role['name'] for role in token_info['roles'] if role],
                            "user_id": token_info.get("user").get("id")}
            em = "Authentication failed"
            return {"success": [{"code": 200, "msg": "{0}".format(em)}]}
        except Exception, e:
            print "Get usermsg error....\n" * 3
            print e
            em = "Authentication success"
            return {"error": [{"code": 401, "msg": "{0}".format(em)}]}
