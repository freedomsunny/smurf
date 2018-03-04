import requests
import json, os
from flask import session

SMURF_HOST = '127.0.0.1:8000'


def login(username, password):
    headers = {'content-type': 'application/json'}
    r = requests.post
    session['server_cookies'] = requests.utils.dict_from_cookiejar(r.cookies)
    return r.json()
    # return _login()


def get_template_groups():
    try:
        cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
        r = requests.get('http://{0}/api/v1.0/servicetemplategroups?include=public'.format(SMURF_HOST), cookies=cookies)
        return r.json()
    except:
        return None


def create_template_group(name, desc, group_type):
    headers = {'content-type': 'application/json'}
    data = {'name': name, 'description': desc, 'public': group_type}
    try:
        cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
        r = requests.post
        return r.json()
    except:
        return None


def create_template(dic):
    headers = {'content-type': 'application/json'}
    try:
        cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
        gid = dic.pop('group_id')
        r = requests.post
        return r.json()
    except:
        return None


def edit_template(tid, gid, dic):
    headers = {'content-type': 'application/json'}
    try:
        cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
        gid = dic.pop('group_id')
        r = requests.put('http://' + SMURF_HOST + '/api/v1.0/servicetemplategroups/' + gid + '/servicetemplates/' + tid,
                         data=json.dumps(dic),
                         cookies=cookies, headers=headers)
        return r.json()
    except:
        return None


def select_templates(gid):
    try:
        cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
        r = requests.get('http://' + SMURF_HOST + '/api/v1.0/servicetemplategroups/' + gid + '/servicetemplates',
                         cookies=cookies)
        return r.json()
    except:
        return None


def select_template(tid, gid):
    try:
        cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
        r = requests.get('http://' + SMURF_HOST + '/api/v1.0/servicetemplategroups/' + gid + '/servicetemplates/' + tid,
                         cookies=cookies)
        return r.json()
    except:
        return None


def delete_templates(gid):
    cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
    r = requests.delete('http://' + SMURF_HOST + '/api/v1.0/servicetemplategroups/' + gid, cookies=cookies)
    return r.json()


def delete_template(gid, tid):
    cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
    r = requests.delete('http://' + SMURF_HOST + '/api/v1.0/servicetemplategroups/' + gid + '/servicetemplates/' + tid,
                        cookies=cookies)
    return r.json()


def commit_project(data):
    headers = {'content-type': 'application/json'}
    try:
        cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
        r = requests.post
        return r.json()
    except:
        return False


def get_projects():
    try:
        cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
        r = requests.get('http://{0}/api/v1.0/projects'.format(SMURF_HOST), cookies=cookies)
        return r.json()
    except:
        return None


def delete_project(pid):
    try:
        cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
        r = requests.delete('http://' + SMURF_HOST + '/api/v1.0/projects/' + pid, cookies=cookies)
        return r.json()
    except:
        return None


def select_project(pid):
    try:
        cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
        r = requests.get('http://' + SMURF_HOST + '/api/v1.0/projects/' + pid, cookies=cookies)
        return r.json()
    except:
        return None


def manage_project(pid, key):
    try:
        cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
        r = requests.post
        return r.json()
    except:
        return None


def get_networks():
    cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
    r = requests.get('http://' + SMURF_HOST + '/api/v1.0/networks', cookies=cookies)
    return r.json()


def delete_network(nid):
    cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
    r = requests.delete('http://' + SMURF_HOST + '/api/v1.0/networks/' + nid, cookies=cookies)
    return r.json()


def create_network(dic):
    headers = {'content-type': 'application/json'}
    cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
    r = requests.post
    return r.json()


def change_network(nid, ids):
    headers = {'content-type': 'application/json'}
    cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
    r = requests.post
    return r.json()


def get_container(pid, sid, cid):
    cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
    r = requests.get('http://' + SMURF_HOST + '/api/v1.0/projects/' + pid + '/services/' + sid + '/containers/' + cid,
                     cookies=cookies)
    return r.json()


def manage_container(pid, sid, cid, action):
    cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
    r = requests.post
    return r.json()


def tamp_log(pid, sid, cid, tamp):
    cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
    params = {'action': 'logs', 'since': tamp}
    r = requests.get(
        'http://' + SMURF_HOST + '/api/v1.0/projects/' + pid + '/services/' + sid + '/containers/' + cid + '/',
        params=params, cookies=cookies)
    return r.json()


def get_users():
    cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
    r = requests.get('http://' + SMURF_HOST + '/api/v1.0/users', cookies=cookies)
    return r.json()


def change_user_type(uid, type_name):
    headers = {'content-type': 'application/json'}
    data = {'type': type_name}
    cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
    r = requests.put('http://' + SMURF_HOST + '/api/v1.0/users/' + uid, cookies=cookies, headers=headers,
                     data=json.dumps(data))
    return r.json()


def service_create(data):
    headers = {'content-type': 'application/json'}
    cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
    r = requests.post
    return r.json()


def service_getall():
    cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
    r = requests.get('http://' + SMURF_HOST + '/api/v1.0/templatecomposes?include=public', cookies=cookies)
    return r.json()


def service_select(_id):
    cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
    r = requests.get('http://' + SMURF_HOST + '/api/v1.0/templatecomposes/' + _id, cookies=cookies)
    return r.json()


def service_delete(_id):
    cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
    r = requests.delete('http://' + SMURF_HOST + '/api/v1.0/templatecomposes/' + _id, cookies=cookies)
    return r.json()


def images_getall():
    cookies = requests.utils.cookiejar_from_dict(session['server_cookies'], cookiejar=None, overwrite=True)
    r = requests.get('http://' + SMURF_HOST + '/api/v1.0/images', cookies=cookies)
    return r.json()
