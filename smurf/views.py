# #!/usr/bin/env python
# # encoding: utf-8
# import json
# import os
# import uuid
# from functools import wraps
#
# import docker
# from flask import render_template, request, redirect, url_for, session, g
# from flask_sockets import Sockets
#
# import smurf.config as config
# from console_thread import consoleThread
# from nets import hpc
# from resources.project import get_project_auth
# from smurf import app
#
# log = app.logger
# sockets = Sockets(app)
# docker_client = docker.client.from_env()
#
#
# # 视图装饰器
# def login_required(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         ck = request.cookies.get('session', None)
#         ck_uid = request.cookies.get('uid', None)
#         uid = session.get('uid', None)
#         is_signout = session.get('signout', None)
#         log.info(is_signout)
#         if ck is None or ck_uid is None or is_signout == '1':
#             log.info('user has signout')
#             return redirect(url_for('login_view'))
#         if ck_uid != uid:
#             log.info('user has wrong session id ')
#             return redirect(url_for('login_view'))
#         return f(*args, **kwargs)
#
#     return decorated_function
#
#
# ################################# login and redirect modules
#
# @app.route('/', methods=['GET'])
# def default():
#     return redirect(url_for('login_view'))
#
#
# @app.route('/login/', methods=['GET', 'POST'])
# def login_view():
#     return
#     error = None
#     if request.method == 'GET':
#         return render_template('login.html')
#     else:
#         username = request.form['username']
#         password = request.form['password']
#         if username is None or password is None:
#             return render_template('login.html', error='sorry,username or password is empty')
#         ret = hpc.login(username, password)
#         if ret['ec'] == 0:
#             session['username'] = username
#             session['user_id'] = ret['user']['id']
#             session['type'] = ret['user']['type']
#             session['signout'] = '0'
#             log.info(username)
#             response = app.make_response(redirect(url_for('index')))
#             return response
#         elif ret['ec'] == 1:
#             return render_template('login.html', error=ret['em'])
#         else:
#             return render_template('login.html', error='sorry,username or password is wrong')
#
#
# @app.route('/index/')
# @login_required
# def index():
#     return render_template('index.html')
#
#
# @app.after_request
# def after_request(response):
#     uid = str(uuid.uuid1());
#     session['uid'] = uid
#     # set session timeout
#     response.set_cookie('uid', value=uid, max_age=config.SESSION_TIME_OUT)
#     return response
#
#
# ################################# project modules
#
# @app.route('/project/')
# @login_required
# def project():
#     dics = hpc.get_projects()
#     log.info(dics)
#     return render_template('project.html', dics=dics['projects'])
#
#
# @app.route('/project/<pid>')
# @login_required
# def project_refrash(pid):
#     dics = hpc.get_projects()
#     return render_template('project.html', dics=dics['projects'], project_id=pid)
#
#
# @app.route('/project/select/<pid>')
# @login_required
# def project_select(pid):
#     dic = hpc.select_project(pid)
#     log.info(dic)
#     return render_template('project_select.html', dic=dic['project'])
#
#
# @app.route('/project/create/')
# @login_required
# def project_create():
#     dics = hpc.get_template_groups()
#     composs = hpc.service_getall()
#     log.info(dics)
#     return render_template('project_create.html', templates=composs['templatecomposes'],
#                            dics=dics['servicetemplategroups'])
#
#
# @app.route('/project/delete/<pid>')
# @login_required
# def project_delete(pid):
#     dics = hpc.delete_project(pid)
#     log.info(dics)
#     return json.dumps(dics)
#
#
# @app.route('/project/auth/<pid>')
# @login_required
# def project_auth(pid):
#     return render_template('project_auth.html', pid=pid)
#
#
# @app.route('/project/manage/', methods=['POST'])
# @login_required
# def project_manage():
#     key = request.form['action']
#     pid = request.form['pid']
#     dic = hpc.manage_project(pid, key)
#     log.info(dic)
#     if dic.get('project', None) is not None:
#         return json.dumps({'ec': 0, 'em': '操作成功'})
#     else:
#         return json.dumps(dic)
#
#
# @app.route('/project/commit/', methods=['POST'])
# @login_required
# def project_commit():
#     dic = json.loads(request.get_data())
#     data = {'name': dic['name'], 'description': dic['description']}
#     services = []
#     for ser in dic['services']:
#         networks = {}
#         for net in ser['networks']:
#             if net['val'] != 'yes' and net.has_key('default'):
#                 networks['default'] = {'ipv4_address': net['val']}
#             elif net['val'] != 'yes':
#                 networks[net['key']] = {'ipv4_address': net['val']}
#             else:
#                 networks['default'] = {}
#         service = {'template_id': ser['id'], 'name': ser['real_service'], 'hostname': ser['hostname'],
#                    'environment': ser['environment'], 'restart': 'always', 'networks': networks}
#         services.append(service)
#     log.info('services is: ')
#     log.info(services)
#     data['services'] = services
#     ret = hpc.commit_project(data)
#     if ret.get('project', None) is None:
#         return json.dumps(ret)
#     else:
#         return json.dumps({'em': 'commit success', 'ec': 0})
#
#
# @app.route('/project/select/templates/', methods=['POST'])
# @login_required
# def project_select_templates():
#     gid = request.form['gid']
#     log.info("gid: " + gid)
#     dics = hpc.select_templates(gid)
#     log.info(dics)
#     return json.dumps(dics.get('servicetemplates', []))
#
#
# @app.route('/project/select/template/', methods=['POST'])
# @login_required
# def project_select_template():
#     tid = request.form['tid']
#     gid = request.form['gid']
#     dics = hpc.select_template(tid, gid)
#     log.info(dics)
#     return json.dumps(dics.get('servicetemplate', None))
#
#
# @app.route('/project/service/<pid>/<sid>')
# @login_required
# def project_service_update(pid, sid):
#     return render_template('project_service.html', pid=pid, sid=sid)
#
#
# @app.route('/project/add/<pid>')
# @login_required
# def project_service_add(pid):
#     return render_template('project_service_add.html', pid=pid)
#
#
# ################################# template modules
#
# @app.route('/template/')
# @login_required
# def template():
#     dic = hpc.get_template_groups()
#     log.info(dic)
#     return render_template('template.html', dics=dic['servicetemplategroups'])
#
#
# @app.route('/template/edit/<gid>/<tid>')
# @login_required
# def template_edit(gid, tid):
#     dic = hpc.select_template(tid, gid)
#     log.info(dic)
#     servicetemplate = dic['servicetemplate']
#     if servicetemplate.get('hostname') is None:
#         servicetemplate['hostname'] = ''
#     aliases = servicetemplate.get('aliases')
#     if aliases is None:
#         aliases = []
#     servicetemplate['aliases'] = ','.join(aliases)
#     dics = hpc.images_getall()
#     images = []
#     for k in dics.keys():
#         for ks in dics[k].keys():
#             for li in dics[k][ks]:
#                 lis = '{0}/{1}:{2}'.format(k, ks, li)
#                 images.append(lis)
#     log.info(servicetemplate)
#     return render_template('template_edit.html', dic=servicetemplate, lists=servicetemplate['environment'].keys(),
#                            length=len(servicetemplate['environment'].keys()), images=json.dumps(images))
#
#
# @app.route('/template/save/', methods=['POST'])
# @login_required
# def template_save():
#     dic = json.loads(request.get_data())
#     log.info(dic)
#     envs = {}
#     for env in dic['t_envs']:
#         if env.get('key', '').strip() == '' or env.get('val', '').strip() == '':
#             continue
#         else:
#             envs[env['key']] = env['val']
#     dic['t_independent'] = True if dic['t_independent'] == '1' else False
#     data = {'name': dic.get('t_name', None),
#             'group_id': dic.get('t_gid', None),
#             'description': dic.get('t_desc', None),
#             'service': dic.get('t_service', None),
#             'hostname': dic.get('t_hostname', None),
#             'aliases': dic.get('t_aliase', None),
#             'independent': dic.get('t_independent', None),
#             'image': dic.get('t_image', None),
#             'environment': envs}
#     if dic.get('depends', None) is not None:
#         data['depends'] = dic['depends']
#     log.info(data)
#     ret = hpc.edit_template(dic['tid'], dic['gid'], data)
#     log.info(ret)
#     if ret.get('servicetemplate', None) is None:
#         return json.dumps(ret)
#     else:
#         return json.dumps({"ec": 0, "em": "update success"})
#
#
# @app.route('/template/create/<gid>')
# @login_required
# def template_create(gid):
#     log.info(gid)
#     groups = hpc.get_template_groups().get('servicetemplategroups', None)
#     ret = None
#     for group in groups:
#         if group['id'] == int(gid):
#             ret = group
#     dics = hpc.images_getall()
#     images = []
#     for k in dics.keys():
#         for ks in dics[k].keys():
#             for li in dics[k][ks]:
#                 lis = '{0}/{1}:{2}'.format(k, ks, li)
#                 images.append(lis)
#     return render_template('template_create.html', group=ret, images=json.dumps(images))
#
#
# @app.route('/template/select/<gid>')
# @login_required
# def template_select(gid):
#     dics = hpc.select_templates(gid)
#     log.info(dics)
#     groups = hpc.get_template_groups().get('servicetemplategroups', None)
#     ret = None
#     for group in groups:
#         if group['id'] == int(gid):
#             ret = group
#     return render_template('template_select.html', dics=dics['servicetemplates'], group=ret)
#
#
# @app.route('/template/delete/<gid>')
# @login_required
# def template_delete(gid):
#     dic = hpc.delete_templates(gid)
#     log.info(dic)
#     if dic.get('servicetemplategroup', None) is not None:
#         dic = {'em': 'delete success', 'ec': 0}
#     return json.dumps(dic)
#
#
# @app.route('/template/del/<gid>/<tid>')
# @login_required
# def template_delete_tid(gid, tid):
#     dic = hpc.delete_template(gid, tid)
#     log.info(dic)
#     if dic.get('servicetemplate', None) is None:
#         return json.dumps(dic)
#     else:
#         return json.dumps({'ec': 0, 'em': 'success'})
#
#
# @app.route('/template/confirm/', methods=['POST'])
# @login_required
# def template_confirm():
#     dic = json.loads(request.get_data())
#     log.info(dic)
#     envs = {}
#     for env in dic['t_envs']:
#         envs[env['key']] = env['val']
#     dic['t_independent'] = True if dic['t_independent'] == '1' else False
#     data = {'name': dic.get('t_name', None),
#             'group_id': dic.get('t_gid', None),
#             'description': dic.get('t_desc', None),
#             'service': dic.get('t_service', None),
#             'hostname': dic.get('t_host', None),
#             'aliases': dic.get('t_alise', None),
#             'independent': dic.get('t_independent', None),
#             'image': dic.get('t_image', None),
#             'environment': envs}
#     if dic.get('depends', None) is not None:
#         data['depends'] = dic['depends']
#     log.info(data)
#     ret = hpc.create_template(data)
#     log.info(ret)
#     if ret.get('servicetemplate', None) is None:
#         return json.dumps(ret)
#     else:
#         return json.dumps({"ec": 0, "em": "create success"})
#
#
# @app.route('/template/group/create/', methods=['POST'])
# @login_required
# def template_group_create():
#     name = request.form['group_name']
#     desc = request.form['group_desc']
#     types = request.form['group_type']
#     group_type = True
#     if types == '1':
#         group_type = False
#     dic = hpc.create_template_group(name, desc, group_type)
#     log.info(dic)
#     if dic is None:
#         return json.dumps({'ec': 1, 'em': 'create fail'})
#     else:
#         return json.dumps({'ec': 0, 'em': '创建成功'})
#
#
# @app.route('/images/')
# @login_required
# def images():
#     dics = hpc.images_getall()
#     images = []
#     log.info(dics)
#     log.info(type(dics))
#     for k in dics.keys():
#         for ks in dics[k].keys():
#             for li in dics[k][ks]:
#                 lis = '{0}/{1}:{2}'.format(k, ks, li)
#                 images.append(lis)
#     log.info(images)
#     return json.dumps(images)
#
#
# ################################# service modules
#
# @app.route('/service/')
# @login_required
# def service():
#     dic = hpc.service_getall();
#     log.info(dic)
#     return render_template('service.html', templates=dic['templatecomposes'])
#
#
# @app.route('/service/select/<sid>')
# @login_required
# def service_sel(sid):
#     dic = hpc.service_select(sid);
#     log.info(dic)
#     return render_template('service_select.html', sid=sid, dics=dic['templatecompose']['templates'],
#                            temp=dic['templatecompose'])
#
#
# @app.route('/service/templates/<_id>')
# @login_required
# def service_select(_id):
#     dic = hpc.service_select(_id);
#     log.info(dic)
#     return json.dumps(dic['templatecompose']['templates'])
#
#
# @app.route('/service/delete/<tid>')
# @login_required
# def service_delete(tid):
#     dic = hpc.service_delete(tid);
#     log.info(dic)
#     if dic.get('templatecompose', None) is not None:
#         dic = {'em': 'delete success', 'ec': 0}
#     return json.dumps(dic)
#
#
# @app.route('/service/create/', methods=['GET', 'POST'])
# @login_required
# def service_create():
#     if request.method == 'GET':
#         dics = hpc.get_template_groups()
#         log.info(dics)
#         return render_template('service_create.html', dics=dics.get('servicetemplategroups', None))
#     if request.method == 'POST':
#         jsons = json.loads(request.get_data())
#         log.info(jsons)
#         ids = []
#         for temp in jsons.get('template_ids', []):
#             ids.append(int(temp))
#         jsons['template_ids'] = ids
#         ret = hpc.service_create(jsons)
#         log.info(ret)
#         if ret.get('templatecompose', None) is None:
#             return json.dumps(ret)
#         else:
#             return json.dumps({'em': 'create success', 'ec': 0})
#
#
# ################################# container modules
#
# @app.route('/container/')
# @login_required
# def container():
#     return render_template('container.html')
#
#
# @app.route('/container/<pid>/<sid>/<cid>')
# @login_required
# def project_container(pid, sid, cid):
#     dic = hpc.get_container(pid, sid, cid)
#     log.info(dic)
#     info = {'pid': pid, 'sid': sid, 'cid': cid}
#     return render_template('project_container.html', dic=dic['container'], info=info)
#
#
# @app.route('/container/<pid>/<sid>/<cid>/<action>')
# @login_required
# def manage_container(pid, sid, cid, action):
#     dic = hpc.manage_container(pid, sid, cid, action)
#     log.info(dic)
#     return json.dumps(dic)
#
#
# @app.route('/container/logs/<pid>/<sid>/<cid>')
# @login_required
# def log_container(pid, sid, cid):
#     info = {'pid': pid, 'sid': sid, 'cid': cid}
#     return render_template('container_log.html', info=info)
#
#
# @app.route('/container/log/<pid>/<sid>/<cid>/<tamp>')
# @login_required
# def log_tamp(pid, sid, cid, tamp):
#     infos = hpc.manage_container(pid, sid, cid, 'logs')
#     dics = []
#     for info in infos['logs']:
#         if len(info) > 0:
#             dics.append(info)
#     return json.dumps(dics)
#
#
# ################################# auth modules
#
# @app.route('/auth/')
# @login_required
# def auth():
#     ret = hpc.get_users()
#     log.info(ret)
#     return render_template('auth.html', users=ret)
#
#
# @app.route('/users/')
# @login_required
# def users():
#     ret = hpc.get_users()
#     log.info(ret)
#     return json.dumps(ret)
#
#
# @app.route('/users/change/', methods=['POST'])
# @login_required
# def user_change():
#     uid = request.form['uid']
#     type_name = request.form['type']
#     ret = hpc.change_user_type(uid, type_name)
#     log.info(ret)
#     return json.dumps(ret)
#
#
# ################################# network modules
#
# @app.route('/network/')
# @login_required
# def network():
#     dic = hpc.get_networks()
#     log.info(dic)
#     return render_template('network.html', dics=dic.get('networks', []))
#
#
# @app.route('/network/delete/<nid>')
# @login_required
# def network_delete(nid):
#     dic = hpc.delete_network(nid)
#     log.info(dic)
#     return json.dumps(dic)
#
#
# @app.route('/network/change/', methods=['POST'])
# @login_required
# def network_change():
#     dic = json.loads(request.get_data())
#     log.info(dic)
#     ret = hpc.change_network(dic['nid'], dic['ids'])
#     log.info(ret)
#     return json.dumps(ret)
#
#
# @app.route('/network/json/')
# @login_required
# def network_json():
#     dic = hpc.get_networks()
#     log.info(dic)
#     return json.dumps(dic)
#
#
# @app.route('/network/create/', methods=['POST'])
# @login_required
# def network_create():
#     dic = json.loads(request.get_data())
#     log.info(dic)
#     ret = hpc.create_network(dic)
#     log.info(ret)
#     log.info(ret.get('network', None))
#     if ret.get('network', None) is None:
#         return json.dumps(ret)
#     else:
#         return json.dumps({'em': '创建成功', 'ec': 0})
#
#
# ################################# signout modules
#
# @app.route('/signout/')
# @login_required
# def signout():
#     session['signout'] = '1'
#     return redirect(url_for('login_view'))
#
#
# # docker console code
# @app.route('/container/exec/<pid>/<cid>/<cname>')
# def container_exec(pid, cid, cname):
#     session['exec_container_id'] = cid
#     session['pid'] = pid
#     role = get_project_auth(pid, g.user)
#     if role is None or role is 'None':
#         return render_template('401.html')
#     session['role'] = role
#     host = os.environ.get('SMURF_HOST')
#     return render_template('console.html', cname=cname, cid=cid, host=host)
#
#
# def create_exec(cid, role):
#     command = ["/bin/sh", "-c",
#                'TERM=xterm-256color; export TERM; [ -x /bin/bash ] && ([ -x /usr/bin/script ] && /usr/bin/script -q -c "/bin/bash" /dev/null || exec /bin/bash) || exec /bin/sh']
#
#     create_exec_options = {
#         "tty": True,
#         "stdin": True,
#     }
#     if role != 'Manager':
#         create_exec_options['user'] = 'loguser'
#     exec_id = docker_client.exec_create(cid, command, **create_exec_options)
#     return exec_id
#
#
# @sockets.route('/container/ws/')
# @login_required
# def echo_socket(ws):
#     pid = session['pid']
#     cid = session['exec_container_id']
#     role = session['role']
#     log.info('role is :' + role)
#     exec_id = create_exec(cid, role)
#     try:
#         sock = docker_client.exec_start(exec_id, detach=False, tty=True, stream=False, socket=True)
#         docker_client.exec_resize(exec_id, height=100, width=118)
#     except:
#         exec_id = create_exec(cid, 'Manager')
#         sock = docker_client.exec_start(exec_id, detach=False, tty=True, stream=False, socket=True)
#         docker_client.exec_resize(exec_id, height=100, width=118)
#     sock.settimeout(600)
#     send = consoleThread(ws, sock)
#     send.start()
#     while not ws.closed:
#         try:
#             message = ws.receive()
#             print 'message:', message
#             if message is not None:
#                 sock.send(message)
#         except Exception as e:
#             print type(e) + ' in send'
#             ws.close()
#             break
#     sock.close()
#     print 'ws close'
