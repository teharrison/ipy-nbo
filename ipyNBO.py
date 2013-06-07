#!/usr/bin/env python

import sys, os, base64, time
import ConfigParser
import utils
from datetime import datetime
from flask import Flask, request, jsonify, url_for
from nova import Nova
from ipydb import IpyDB
from proxy import Proxy

# global variables
app = Flask(__name__)
cfg = ConfigParser.ConfigParser()
dbc = {}

# load config
try:
    cfg.read(['config/config.ini'])
except:
    sys.stderr.write("Error: Could not load configuration\n")
    sys.exit(1)

# db config
try:
    dbc = { 'host': 'localhost',
            'database': cfg.get("psql", "name"),
            'user': cfg.get("psql", "user"),
            'password': cfg.get("psql", "password") }
except:
    sys.stderr.write("Error: Missing postgresql config\n")
    sys.exit(1)

# overwrite default error handeling
@app.errorhandler(400)
def bad_request(error=None):
    msg = 'Bad Request: %s'%request.url
    return return_json(None, msg, 400)

@app.errorhandler(404)
def not_found(error=None):
    msg = 'Not Found: %s is not a valid resource'%request.url
    return return_json(None, msg, 404)

@app.errorhandler(405)
def not_allowed(error=None):
    msg = 'Method Not Allowed (%s): %s'%(request.method, request.url)
    return return_json(None, msg, 405)

@app.errorhandler(500)
def internal_error(error=None):
    msg = 'Internal Server Error: %s'%request.url
    return return_json(None, msg, 500)

# authentication
def check_auth(headers):
    if ('Authorization' in headers) and headers['Authorization'].startswith('Basic '):
        try:
            auth = base64.b64decode(headers['Authorization'][6:])
            (username, password) = auth.split(':')
            return {'username': username, 'password': password, 'error': None}
        except:
            return {'username': None, 'error': 'Unauthorized: '+sys.exc_info()[0].__doc__}
    elif ('Authorization' in headers) and headers['Authorization'].startswith('OAuth '):
        try:
            token = headers['Authorization'][6:]
            oauth = utils.get_oauth(token)
            if oauth['status'] != 200:
                return {'username': None, 'error': 'Unauthorized: '+oauth['error']}
            else:
                oauth['data']['error'] = None
                return oauth['data']
        except:
            return {'username': None, 'error': 'Unauthorized: '+sys.exc_info()[0].__doc__}
    else:
        return {'username': None, 'error': 'Unauthorized: missing/invalid Authorization header'}

# our resources
@app.route('/')
def api_root():
    data = [ { 'method': 'GET',
               'description': 'view all db entries',
               'url': '/status' },
             { 'method': 'GET',
               'description': 'view db entry by vm id',
               'url': '/status/vm/<vmid>'},
             { 'method': 'DELETE',
               'description': 'delete db entry by vm id',
               'url': '/status/vm/<vmid>'},
             { 'method': 'GET',
               'description': 'view db entry by user name',
               'url': '/status/user/<name>'},
             { 'method': 'GET',
               'description': 'view proxy status (Basic auth - nova admin)',
               'url': '/proxy'},
             { 'method': 'POST',
               'description': 'add user to proxy list (OAuth auth - user token)',
               'url': '/proxy'},
             { 'method': 'DELETE',
               'description': 'add user to proxy list (Basic auth - nova admin)',
               'url': '/proxy?user=<string>'},
             { 'method': 'GET',
               'description': 'view all nova vms (Basic auth - nova)',
               'url': '/nova?type=<string>' },
             { 'method': 'POST',
               'description': 'create ipyNB vm (Basic auth - nova)',
               'url': '/nova?type=<string>&name=<string>' },
             { 'method': 'GET',
               'description': 'view nova vm (Basic auth - nova)',
               'url': '/nova/<vmid>?type=<string>' },
             { 'method': 'PUT',
               'description': 'reboot ipynb vm (Basic auth - nova)',
               'url': '/nova/<vmid>?type=<string>' },
             { 'method': 'DELETE',
               'description': 'delete ipynb vm (Basic auth - nova)',
               'url': '/nova/<vmid>?type=<string>' },
             { 'method': 'GET',
               'description': 'nova usage status for type (Basic auth - nova)',
               'url': '/nova/usage?type=<string>&verbosity=<max|min>'},
             { 'method': 'POST',
               'description': 'start ipython on vm (Basic auth - nova)',
               'url': '/ipython/<vmid>?build=<none|ipython|all>' },
             { 'method': 'PUT',
               'description': 'reboot ipython on vm (Basic auth - nova)',
               'url': '/ipython/<vmid>' },
             { 'method': 'DELETE',
               'description': 'stop ipython on vm (Basic auth - nova)',
               'url': '/ipython/<vmid>' } ]
    return return_json(data)

# return list of VM objs from DB
@app.route('/status', methods=['GET'])
def api_status_all():
    ipydb = IpyDB(dbc)
    if ipydb.error:
        return return_json(None, 'Service Unavailable: unable to connect to database, %s'%ipydb.error, 503)
    res = ipydb.list()
    ipydb.exit()
    return return_json(res) if res else return_json(None, 'Internal Server Error: no data available', 500)

# return VM obj from DB for id
@app.route('/status/vm/<vmid>', methods=['GET', 'DELETE'])
def api_status_vm(vmid):
    ipydb = IpyDB(dbc)
    if ipydb.error:
        return return_json(None, 'Service Unavailable: unable to connect to database, %s'%ipydb.error, 503)
    response = return_json(None, 'Method Not Allowed (%s): %s'%(request.method, request.url), 405)
    if request.method == 'GET':
        res = ipydb.get('id', vmid)
        response = return_json(res) if res else return_json(None, "Internal Server Error: data not available for VM '%s'"%vmid, 500)
    elif request.method == 'DELETE':
        ipydb.delete(vmid)
        response = return_json(vmid+' is deleted from DB')
    ipydb.exit()
    return response
    
# return VM obj from DB for user
@app.route('/status/user/<name>', methods=['GET'])
def api_status_user(name):
    ipydb = IpyDB(dbc)
    if ipydb.error:
        return return_json(None, 'Service Unavailable: unable to connect to database, %s'%ipydb.error, 503)
    res = ipydb.get('user', name)
    ipydb.exit()
    return return_json(res) if res else return_json(None, "Internal Server Error: data not available for user '%s'"%name, 500)

@app.route('/proxy', methods=['GET', 'POST', 'DELETE'])
def api_proxy():
    pcfg = dict(cfg.items('proxy'))
    auth = check_auth(req.headers)
    if auth['error']:
        return return_json(None, auth['error'], 401)
    ipydb = IpyDB(dbc)
    if ipydb.error:
        return return_json(None, 'Service Unavailable: unable to connect to database, %s'%ipydb.error, 503)
    pkey = vmkey = os.path.join(cfg.get("ipyno", "sshdir"), cfg.get('nova-admin', "vm_key")+'.pem')
    proxy = Proxy(pcfg['ip_internal'], pcfg['user'], pcfg['port'], pcfg['config'], pkey, pcfg['template'])
    response = return_json(None, 'Method Not Allowed (%s): %s'%(request.method, request.url), 405)
    # return list of server objs from proxy
    if request.method == 'GET':
        nova = Nova(auth, cfg.get('nova-admin', "tenant"), cfg.get('nova-admin', "auth_url"))
        if nova.error:
            return return_json(None, nova.error['error'], nova.error['status'])
        
            
        cmd = "cat "+pcfg['config']
        res = utils.run_remote_cmd(pcfg['ip_internal'], pcfg['user'], cfg.get('nova-admin', "vm_key"), cmd)
        if res['stderr']:
            response = return_json(None, 'Internal Server Error: %s'%res['stderr'], 500)
        else:
            data = utils.parse_nginx(ipydb, res['stdout'])
            response = return_json({'ip_internal': pcfg['ip_internal'], 'ip_external': pcfg['ip_external'], 'server': data})
    # return server obj from proxy for user - if does not exist create it
    elif request.method == 'POST':
        res = ipydb.get('user', auth['username'])
        # user already has a proxy
        if res:
            return return_json({'ip_internal': pcfg['ip_internal'], 'ip_external': pcfg['ip_external'], 'server': res})
        # set proxy for user - get free port, add to db, add to nginx config
        vm = ipydb.reserve()
        if not vm:
            return return_json(None, 'Service Unavailable: no free ipython servers available', 503)
        new_port = ipydb.next_port(int(pcfg["pstart"]), int(pcfg["pend"]))
        vm = ipydb.update(vm['id'], user=auth['username'], port=new_port)
        template = open(os.path.join('config', pcfg['template']), 'r').read()
        server_cfg = template.format(port=new_port, ip=vm['ip'], ipy_port=pcfg['port'])
        cmd = 'sudo echo "%s" >> %s; sudo /etc/init.d/nginx reload'%(server_cfg, pcfg['config'])
        res = utils.run_remote_cmd(pcfg['ip_internal'], pcfg['user'], cfg.get('nova-admin', "vm_key"), cmd)
        if res['stderr']:
            response = return_json(None, 'Internal Server Error: %s'%res['stderr'], 500)
        else:
            vm['text'] = server_cfg
            response = return_json({'ip_internal': pcfg['ip_internal'], 'ip_external': pcfg['ip_external'], 'server': vm})
    # delete vm from proxy based on user, remove proxy/user info from db
    elif request.method == 'DELETE':
        user = request.args['user'] if 'user' in request.args else None
        if not user:
            return {'status': 400, 'error': "Bad Request: missing user", 'data': None}
        vm = ipydb.get('user', user)
        if not vm:
            return {'status': 400, 'error': "Bad Request: missing user", 'data': None}
        ipydb.delete(vm['id'])
        
    ipydb.exit()
    return response

@app.route('/nova', methods=['GET', 'POST'])
def api_nova():       
    try_nova = get_nova(request)
    if try_nova['status'] != 200:
        return return_json(None, try_nova['error'], try_nova['status'])
    nova = try_nova['data']
    ncfg = dict(cfg.items(try_nova['section']))
    response = return_json(None, 'Method Not Allowed (%s): %s'%(request.method, request.url), 405)
    if request.method == 'GET':
        res = nova.server()
        response = return_json(res['data']) if res['status'] == 200 else return_json(None, res['error'], res['status'])
    elif request.method == 'POST':
        ipydb = IpyDB(dbc)
        if ipydb.error:
            return return_json(None, 'Service Unavailable: unable to connect to database, %s'%ipydb.error, 503)
        name = request.args['name'] if 'name' in request.args else 'ipynb_%d'%ipydb.next_val()
        res  = nova.create(name, ncfg["image"], ncfg["flavor"], ncfg["security"], ncfg["vm_key"])
        if res['status'] == 200:
            vmid = res['data']['id']
            while len(res['data']['addresses']) == 0:
                time.sleep(30)
                res = nova.server(vmid)
            ipydb.insert(vmid, name, res['data']['addresses'][0], ncfg["vm_key"])
            response = return_json(res['data'])
        else:
            response = return_json(None, res['error'], res['status'])
        ipydb.exit()
    return response

@app.route('/nova/<vmid>', methods=['GET', 'PUT', 'DELETE'])
def api_nova_server(vmid):
    try_nova = get_nova(request)
    if try_nova['status'] != 200:
        return return_json(None, try_nova['error'], try_nova['status'])
    nova = try_nova['data']
    response = return_json(None, 'Method Not Allowed (%s): %s'%(request.method, request.url), 405)
    if request.method == 'GET':
        res = nova.server(vmid)
        response = return_json(res['data']) if res['status'] == 200 else return_json(None, res['error'], res['status'])
    elif request.method == 'PUT':
        res = nova.reboot(vmid)
        response = return_json(vmid+' is rebooting') if res['status'] == 200 else return_json(None, res['error'], res['status'])
    elif request.method == 'DELETE':
        ipydb = IpyDB(dbc)
        if ipydb.error:
            return return_json(None, 'Service Unavailable: unable to connect to database, %s'%ipydb.error, 503)
        res = nova.delete(vmid)
        if res['status'] == 200:
            ipydb.delete(vmid)
            response = return_json(vmid+' is deleting')
        else:
            response = return_json(None, res['error'], res['status'])
        ipydb.exit()
    return response

@app.route('/nova/usage', methods=['GET'])
def api_nova_usage():
    full = True if ('verbosity' in request.args) and (request.args['verbosity'] == 'max') else False
    try_nova = get_nova(request)
    if try_nova['status'] != 200:
        return return_json(None, try_nova['error'], try_nova['status'])
    nova = try_nova['data']
    res = nova.available(full)
    return return_json(res['data']) if res['status'] == 200 else return_json(None, res['error'], res['status'])

@app.route('/ipython/<vmid>', methods=['POST', 'PUT', 'DELETE'])
def api_ipy(vmid):
    try_nova = get_nova(request)
    if try_nova['status'] != 200:
        return return_json(None, try_nova['error'], try_nova['status'])
    ipydb = IpyDB(dbc)
    if ipydb.error:
        return return_json(None, 'Service Unavailable: unable to connect to database, %s'%ipydb.error, 503)
    ipycfg = dict(cfg.items('ipython'))
    vminfo = ipydb.get('id', vmid)
    if not vminfo:
        return_json(None, "Internal Server Error: data not available for VM '%s'"%vmid, 500)
    vmkey = os.path.join(cfg.get("ipyno", "sshdir"), vminfo['vm_key']+'.pem')
    if not os.path.isfile(vmkey):
        return return_json(None, 'Internal Server Error: missing private key (%s) for VM %s'%(vminfo['vm_key'], vmid), 500)
    response = return_json(None, 'Method Not Allowed (%s): %s'%(request.method, request.url), 405)
    if request.method == 'POST':
        build = request.args['build'] if 'build' in request.args else 'none'
        if build not in ['none', 'ipython', 'all']:
            return return_json(None, "Bad Request: 'build' must be one of: none, ipython, all", 400)
        cmd = 'sudo %s/%s -b %s -s %s'%(ipycfg['init_dir'], ipycfg['init_script'], build, cfg.get("shock", "url"))
        res = utils.run_remote_cmd(vminfo['vm_ip'], ipycfg['user'], vmkey, cmd)
        if res['stderr']:
            response = return_json(None, 'Internal Server Error: %s'%res['stderr'], 500)
        else:
            ipydb.update(vmid, ipy=True)
            response = return_json('initalized ipython on %s (%s)'%(vminfo['vm_name'], vmid))
    elif request.method == 'PUT':
        cmd = 'sudo %s/%s; sleep 3; sudo %s/%s -a %s -s %s'%(ipycfg['run_dir'], ipycfg['stop_script'], ipycfg['run_dir'], ipycfg['start_script'], cfg.get("shock", "auth"), cfg.get("shock", "url"))
        res = utils.run_remote_cmd(vminfo['vm_ip'], ipycfg['user'], vmkey, cmd)
        if res['stderr']:
            response = return_json(None, 'Internal Server Error: %s'%res['stderr'], 500)
        else:
            ipydb.update(vmid, ipy=True)
            response = return_json('restarted ipython on %s (%s)'%(vminfo['vm_name'], vmid))
    elif request.method == 'DELETE':
        cmd = 'sudo %s/%s'%(ipycfg['run_dir'], ipycfg['stop_script'])
        res = utils.run_remote_cmd(vminfo['vm_ip'], ipycfg['user'], vmkey, cmd)
        if res['stderr']:
            response = return_json(None, 'Internal Server Error: %s'%res['stderr'], 500)
        else:
            ipydb.update(vmid, ipy=False)
            response = return_json('stoped ipython on %s (%s)'%(vminfo['vm_name'], vmid))
    ipydb.exit()
    return response

def get_nova(req):
    sect = 'nova-'+req.args['type'] if 'type' in req.args else 'nova-ipy'
    if not cfg.has_section(sect):
        return {'status': 400, 'error': "Bad Request: unknown nova type '%s'"%req.args['type'], 'data': None}
    auth = check_auth(req.headers)
    if auth['error']:
        return {'status': 401, 'error': auth['error'], 'data': None}
    nova = Nova(auth, cfg.get(sect, "tenant"), cfg.get(sect, "auth_url"))
    if nova.error:
        return nova.error
    return {'status': 200, 'error': None, 'data': nova, 'section': sect}

def return_json(data, err=None, status=200):
    obj = { 'data': data,
            'error': err,
            'status': status,
            'timestamp': str(datetime.now()) }
    resp = jsonify(obj)
    resp.status_code = status
    return resp

if __name__ == '__main__':
     app.run('0.0.0.0', int(cfg.get("ipyno", "port")), debug=True)
