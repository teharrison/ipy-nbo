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

# load config
try:
    cfg.read(['config/config.ini'])
except:
    sys.stderr.write("Error: Could not load configuration\n")
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
            oauth = utils.get_oauth(cfg.get('ipyno', 'auth_url'), token)
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
               'description': 'view all db entries (Basic auth - psql)',
               'url': '/status' },
             { 'method': 'PUT',
               'description': "update 'status' on all db entries from nova-pool (Basic auth - psql)",
               'url': '/status' },
             { 'method': 'GET',
               'description': 'view db entry by vm id (Basic auth - psql)',
               'url': '/status/vm/<vmid>'},
             { 'method': 'DELETE',
               'description': 'delete db entry by vm id (Basic auth - psql)',
               'url': '/status/vm/<vmid>'},
             { 'method': 'GET',
               'description': 'view db entry by user name (Basic auth - psql)',
               'url': '/status/user/<name>'},
             { 'method': 'GET',
               'description': 'view status of daemon (Basic auth - psql)',
               'url': '/status/daemon'},
             { 'method': 'GET',
               'description': 'view proxy status (Basic auth - nova-admin)',
               'url': '/proxy?user=<string>'},
             { 'method': 'POST',
               'description': 'add user to proxy list (OAuth auth - user token)',
               'url': '/proxy'},
             { 'method': 'DELETE',
               'description': 'delete user from proxy list (Basic auth - nova-admin)',
               'url': '/proxy?user=<string>'},
             { 'method': 'GET',
               'description': 'view all nova vms (Basic auth - nova-pool)',
               'url': '/nova' },
             { 'method': 'POST',
               'description': 'create ipyNB vm (Basic auth - nova-pool)',
               'url': '/nova?name=<string>' },
             { 'method': 'GET',
               'description': 'view nova vm (Basic auth - nova-pool)',
               'url': '/nova/<vmid>' },
             { 'method': 'PUT',
               'description': 'reboot ipynb vm (Basic auth - nova-pool)',
               'url': '/nova/<vmid>' },
             { 'method': 'DELETE',
               'description': 'delete ipynb vm (Basic auth - nova-pool)',
               'url': '/nova/<vmid>' },
             { 'method': 'GET',
               'description': 'nova usage status for pool tenant (Basic auth - nova-pool)',
               'url': '/nova/usage?verbosity=<max|min>'},
             { 'method': 'POST',
               'description': 'start ipython on vm (Basic auth - psql)',
               'url': '/ipython/<vmid>?build=<none|ipython|all>' },
             { 'method': 'PUT',
               'description': 'reboot ipython on vm (Basic auth - psql)',
               'url': '/ipython/<vmid>' },
             { 'method': 'DELETE',
               'description': 'stop ipython on vm (Basic auth - psql)',
               'url': '/ipython/<vmid>' } ]
    return return_json(data)

# return list of VM objs from DB
@app.route('/status', methods=['GET', 'PUT'])
def api_status_all():
    try_ipydb = get_ipydb(request, True)
    if try_ipydb['status'] != 200:
        return return_json(None, try_ipydb['error'], try_ipydb['status'])
    ipydb  = try_ipydb['data']
    all_vm = ipydb.list()
    if not all_vm:
        response = return_json(None, 'Internal Server Error: no data available', 500)
    # return list of VM objs from DB
    elif request.method == 'GET':
        response = return_json(all_vm)
    # update 'status' of VM objs in DB from nova-pool
    elif request.method == 'PUT':
        ncfg = dict(cfg.items('nova-pool'))
        nova = Nova({'username': ncfg["user"], 'password': ncfg["password"]}, ncfg["tenant"], ncfg["auth_url"])
        if nova.error:
            return return_json(None, nova.error['error'], nova.error['status'])
        data = nova.server()
        if data['status'] == 200:
            updated = []
            servers = dict([(x['id'], x) for x in data['data']])
            for vm in all_vm:
                if vm['id'] in servers:
                    new = ipydb.update(vm['id'], status=servers[vm['id']]['status'])
                else:
                    new = ipydb.update(vm['id'], status='UNKNOWN')
                updated.append(new)
            response = return_json(updated)
        else:
            response = return_json(all_vm)
    ipydb.exit()
    return response

@app.route('/status/vm/<vmid>', methods=['GET', 'DELETE'])
def api_status_vm(vmid):
    try_ipydb = get_ipydb(request, True)
    if try_ipydb['status'] != 200:
        return return_json(None, try_ipydb['error'], try_ipydb['status'])
    ipydb = try_ipydb['data']
    response = return_json(None, 'Method Not Allowed (%s): %s'%(request.method, request.url), 405)
    # return VM obj from DB for id
    if request.method == 'GET':
        res = ipydb.get('id', vmid)
        response = return_json(res) if res else return_json(None, "Internal Server Error: data not available for VM '%s'"%vmid, 500)
    # delete VM obj from DB for id
    elif request.method == 'DELETE':
        ipydb.delete(vmid)
        response = return_json(vmid+' is deleted from DB')
    ipydb.exit()
    return response
    
# return VM obj from DB for user
@app.route('/status/user/<name>', methods=['GET'])
def api_status_user(name):
    try_ipydb = get_ipydb(request, True)
    if try_ipydb['status'] != 200:
        return return_json(None, try_ipydb['error'], try_ipydb['status'])
    ipydb = try_ipydb['data']
    res = ipydb.get('user', name)
    ipydb.exit()
    return return_json(res) if res else return_json(None, "Internal Server Error: data not available for user '%s'"%name, 500)

# get daemon status - use ipydb auth
@app.route('/status/daemon', methods=['GET'])
def api_status_daemon():
    try_ipydb = get_ipydb(request, True)
    if try_ipydb['status'] != 200:
        return return_json(None, try_ipydb['error'], try_ipydb['status'])
    prefix = cfg.get('ipyno', 'logdir')+'/ipyno'
    data = {'pid': None, 'stderr': None, 'stdout': None}
    try:
        data['pid'] = int( open(prefix+'.pid', 'r').read().strip() )
    except:
        pass
    try:
        data['stderr'] = open(prefix+'.err', 'r').read().strip()
    except:
        pass
    try:
        data['stdout'] = open(prefix+'.out', 'r').read().strip()
    except:
        pass
    data['running'] = utils.pid_exists(data['pid'])
    return return_json(data)

@app.route('/proxy', methods=['GET', 'POST', 'DELETE'])
def api_proxy():
    user = request.args['user'] if 'user' in request.args else None
    pkey = os.path.join(cfg.get("ipyno", "sshdir"), cfg.get('nova-admin', "vm_key")+'.pem')
    pcfg = dict(cfg.items('proxy'))
    try_ipydb = get_ipydb(request, False)
    if try_ipydb['status'] != 200:
        return return_json(None, try_ipydb['error'], try_ipydb['status'])
    ipydb = try_ipydb['data']
    proxy = Proxy(pcfg, pkey)
    response = return_json(None, 'Method Not Allowed (%s): %s'%(request.method, request.url), 405)
    # return list of server objs from proxy (nova-admin auth)
    if request.method == 'GET':
        try_nova = get_nova(request, 'nova-admin')
        if try_nova['status'] != 200:
            response = return_json(None, try_nova['error'], try_nova['status'])
        elif not user:
            response = return_json(None, "Bad Request: missing user", 400)
        else:
            data = proxy.get_server(user)
            response = return_json(data['data']) if data['status'] == 200 else return_json(None, data['error'], data['status'])
    # return server obj from proxy for user - if does not exist create it (add user to proxy and db) (oauth auth)
    elif request.method == 'POST':
        auth = check_auth(request.headers)
        if auth['error']:
            return return_json(None, auth['error'], 401)
        res = ipydb.get('user', auth['username'])
        # user already has a proxy
        if res:
            data = proxy.get_server(auth['username'])
            return return_json(data['data']) if data['status'] == 200 else return_json(None, data['error'], data['status'])
        # set proxy for user - get free port, add to db, add to nginx config
        vm = ipydb.reserve()
        port = ipydb.next_port(int(pcfg["pstart"]), int(pcfg["pend"]))
        if vm and port:
            vm = ipydb.update(vm['id'], user=auth['username'], port=port)
            data = proxy.add_server(auth['username'], vm['ip'], port)
            response = return_json(data['data']) if data['status'] == 200 else return_json(None, data['error'], data['status'])
        else:
            response = return_json(None, 'Service Unavailable: no free ipython servers available', 503)
    # delete vm from proxy based on user, remove proxy/user info from db (nova auth)
    elif request.method == 'DELETE':
        try_nova = get_nova(request, 'nova-admin')
        if try_nova['status'] != 200:
            response = return_json(None, try_nova['error'], try_nova['status'])
        elif not user:
            response = return_json(None, "Bad Request: missing user", 400)
        else:
            vm = ipydb.get('user', user)
            # user in DB and vaild auth - now we delete
            if vm:
                ipydb.drop_user(vm['id'])
                res = proxy.remove_server(user)
                response = return_json("user '%s' removed"%user) if res['status'] == 200 else return_json(None, res['error'], res['status'])
            else:
                response = return_json(None, "Bad Request: invalid user %s"%user, 400)
    ipydb.exit()
    return response

@app.route('/nova', methods=['GET', 'POST'])
def api_nova():
    try_nova = get_nova(request, 'nova-pool')
    if try_nova['status'] != 200:
        return return_json(None, try_nova['error'], try_nova['status'])
    nova = try_nova['data']
    ncfg = dict(cfg.items('nova-pool'))
    response = return_json(None, 'Method Not Allowed (%s): %s'%(request.method, request.url), 405)
    # list all VMs in nova-pool
    if request.method == 'GET':
        res = nova.server()
        response = return_json(res['data']) if res['status'] == 200 else return_json(None, res['error'], res['status'])
    # launch VM in nova pool - add to DB
    elif request.method == 'POST':
        try_ipydb = get_ipydb(request, False)
        if try_ipydb['status'] != 200:
            return return_json(None, try_ipydb['error'], try_ipydb['status'])
        ipydb = try_ipydb['data']
        name  = request.args['name'] if 'name' in request.args else 'ipynb_%d'%ipydb.next_val()
        res   = nova.create(name, ncfg["image"], ncfg["flavor"], ncfg["security"], ncfg["vm_key"])
        if res['status'] == 200:
            vmid = res['data']['id']
            while len(res['data']['addresses']) == 0:
                time.sleep(30)
                res = nova.server(vmid)
            ipydb.insert(vmid, name, res['data']['addresses'][0], ncfg["vm_key"], res['status'])
            response = return_json(res['data'])
        else:
            response = return_json(None, res['error'], res['status'])
        ipydb.exit()
    return response

@app.route('/nova/<vmid>', methods=['GET', 'PUT', 'DELETE'])
def api_nova_server(vmid):
    try_nova = get_nova(request, 'nova-pool')
    if try_nova['status'] != 200:
        return return_json(None, try_nova['error'], try_nova['status'])
    nova = try_nova['data']
    response = return_json(None, 'Method Not Allowed (%s): %s'%(request.method, request.url), 405)
    # info for given VM in nova-pool
    if request.method == 'GET':
        res = nova.server(vmid)
        response = return_json(res['data']) if res['status'] == 200 else return_json(None, res['error'], res['status'])
    # reboot given VM in nova-pool
    elif request.method == 'PUT':
        res = nova.reboot(vmid)
        response = return_json(vmid+' is rebooting') if res['status'] == 200 else return_json(None, res['error'], res['status'])
    # terminate given VM in nova-pool - delete from db
    elif request.method == 'DELETE':
        try_ipydb = get_ipydb(request, False)
        if try_ipydb['status'] != 200:
            return return_json(None, try_ipydb['error'], try_ipydb['status'])
        ipydb = try_ipydb['data']
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
    try_nova = get_nova(request, 'nova-pool')
    if try_nova['status'] != 200:
        return return_json(None, try_nova['error'], try_nova['status'])
    nova = try_nova['data']
    res = nova.available(full)
    return return_json(res['data']) if res['status'] == 200 else return_json(None, res['error'], res['status'])

@app.route('/ipython/<vmid>', methods=['POST', 'PUT', 'DELETE'])
def api_ipy(vmid):
    # authenticate through db connection
    try_ipydb = get_ipydb(request, True)
    if try_ipydb['status'] != 200:
        return return_json(None, try_ipydb['error'], try_ipydb['status'])
    ipydb  = try_ipydb['data']
    ipycfg = dict(cfg.items('ipython'))
    vminfo = ipydb.get('id', vmid)
    if not vminfo:
        return return_json(None, "Internal Server Error: data not available for VM '%s'"%vmid, 500)
    vmkey = os.path.join(cfg.get("ipyno", "sshdir"), vminfo['vm_key']+'.pem')
    if not os.path.isfile(vmkey):
        return return_json(None, 'Internal Server Error: missing private key (%s) for VM %s'%(vminfo['vm_key'], vmid), 500)
    # run init script for ipython on givien vm
    if request.method == 'POST':
        build = request.args['build'] if 'build' in request.args else 'none'
        if build not in ['none', 'ipython', 'all']:
            return return_json(None, "Bad Request: 'build' must be one of: none, ipython, all", 400)
        cmd = 'sudo %s/%s -b %s -s %s'%(ipycfg['init_dir'], ipycfg['init_script'], build, cfg.get("shock", "url"))
        ipy_status = ['initalized', True]
    # stop then start ipython on givien vm (used for both restart and start)
    elif request.method == 'PUT':
        cmd = 'sudo %s/%s; sleep 3; sudo %s/%s -a %s -s %s'%(ipycfg['run_dir'], ipycfg['stop_script'], ipycfg['run_dir'], ipycfg['start_script'], cfg.get("shock", "auth"), cfg.get("shock", "url"))
        ipy_status = ['restarted', True]
    # stop ipython on givien vm 
    elif request.method == 'DELETE':
        cmd = 'sudo %s/%s'%(ipycfg['run_dir'], ipycfg['stop_script'])
        ipy_status = ['stoped', False]
    else:
        return return_json(None, 'Method Not Allowed (%s): %s'%(request.method, request.url), 405)
    res = utils.run_remote_cmd(vminfo['vm_ip'], ipycfg['user'], vmkey, cmd)
    if res['stderr']:
        return return_json(None, 'Internal Server Error: %s'%res['stderr'], 500)
    ipydb.update(vmid, ipy=ipy_status[1])
    ipydb.exit()
    return return_json('%s ipython on %s (%s)'%(ipy_status[0], vminfo['vm_name'], vmid))

def get_nova(req, sect):
    if not cfg.has_section(sect):
        return {'status': 500, 'error': "Internal Server Error: malformed config file", 'data': None}
    auth = check_auth(req.headers)
    if auth['error']:
        return {'status': 401, 'error': auth['error'], 'data': None}
    nova = Nova(auth, cfg.get(sect, "tenant"), cfg.get(sect, "auth_url"))
    if nova.error:
        return nova.error
    return {'status': 200, 'error': None, 'data': nova}

def get_ipydb(req, use_auth=False):
    dbc = {'host': 'localhost', 'database': cfg.get("psql", "name")}
    if use_auth:
        auth = check_auth(req.headers)
        if auth['error']:
            return {'status': 401, 'error': auth['error'], 'data': None}
        dbc['user'] = 'username'
        dbc['password'] = 'password'
    else:
        dbc['user'] = cfg.get("psql", "user")
        dbc['password'] = cfg.get("psql", "password")
    ipydb = IpyDB(dbc)
    if ipydb.error:
        return {'status': 503, 'error': 'Service Unavailable: unable to connect to database, %s'%ipydb.error, 'data': None}
    return {'status': 200, 'error': None, 'data': ipydb}

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
