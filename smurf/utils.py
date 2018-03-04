import commands
import logging
import random
import json
from smurf import  cache
from smurf import config
from smurf.api_requests.api_requests import post_http, get_http

logger = logging.getLogger(__name__)


def exec_cmd(cmd):
    try:
        if not isinstance(cmd, list):
            em = "command must be a list object"
            return {"error": [{"code": '', "msg": "{0}".format(em)}]}
        cmd_str = ' '.join(cmd)
        msg = "Running Command: {0}".format(cmd)
        print msg
        logger.debug(msg)
        result = commands.getstatusoutput(cmd_str)
        if result[0] != 0:
            em = "exec cmd error cmd: [{0}]\nerror: [{1}]".format(cmd, result[1])
            return {"error": [{"code": result[0], "msg": "{0}".format(em)}]}
        else:
            return {"success": [{"code": result[0], "msg": ""}]}
    except Exception as e:
        em = "unknow error msg: %s".format(e)
        logger.debug(em)
        return {"error": [{"code": 500, "msg": "{0}".format(em)}]}


def random_mac():
    mac_list = ["02", "42"]
    for i in range(1, 5):
        rand_str = "".join(random.sample("0123456789abcdef", 2))
        mac_list.append(rand_str)
    rand_mac = ":".join(mac_list)
    return rand_mac


def get_token(username=config.username, password=config.password, tenant=config.tenant):
    backend = cache.Backend()
    if tenant:
        token = backend.get("keystone_tenant_endpoint")
        if not token:
            data = {"auth":
                        {"passwordCredentials":
                             {"username": username,
                              "password": password},
                         'tenantName': tenant
                         },
                    }
            r = post_http(method='post', url='%s/tokens' % config.keystone_admin_endpoint,
                          data=json.dumps(data))
            if r.status_code == 200 and r.json().get('access', ''):
                token = r.json().get('access').get("token").get("id")
                backend.set("keystone_tenant_endpoint", token)
                return r.json()['access']['token']['id']
            else:
                return False
        return token
    else:
        token = backend.get("keystone_admin_endpoint")
        if not token:
            data = {"auth":
                        {"passwordCredentials":
                             {"username": username,
                              "password": password
                              },
                         "tenantName": tenant}
                    }
            try:
                # first get token from redis. if not get from keystone
                r = post_http(method='post', url='%s/tokens' % config.keystone_admin_endpoint,
                              data=json.dumps(data))
                data = r.json()
                if r.status_code == 200 and data.get("access"):
                    token = data.get('access').get("token").get("id")
                    if not token:
                        em = "can not get admin token"
                        logger.warn(em)
                        return False
                    backend.set("keystone_admin_endpoint", token)
                    return token
                else:
                    return False
            except Exception as e:
                logger.warn(e)
                return False
        return token