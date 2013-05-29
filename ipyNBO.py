#!/usr/bin/env python

import sys, base64
import ConfigParser
import utils
from os.path import join
from datetime import datetime
from flask import Flask, request, jsonify, url_for
from nova import Nova
from ipydb import IpyDB

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
def bad_request():
    msg = 'Bad Request: %s'%request.url
    return return_json(None, msg, 400)

@app.errorhandler(404)
def not_found():
    msg = 'Not Found: %s'%request.url
    return return_json(None, msg, 404)

@app.errorhandler(405)
def not_allowed():
    msg = 'Method Not Allowed (%s): %s'%(request.method, request.url)
    return return_json(None, msg, 405)

@app.errorhandler(500)
def internal_error():
    msg = 'Internal Server Error: %s'%request.url
    return return_json(None, msg, 500)

# authentication
def check_auth(req):
    if not (('Authorization' in req.headers) and req.headers['Authorization'].startswith('Basic ')):
        return {'user': None, 'pswd': None, 'error': 'Unauthorized: missing Authorization header'}
    try:
        auth = base64.b64decode(req.headers['Authorization'][6:])
        (username, password) = auth.split(':')
        return {'user': username, 'pswd': password, 'error': None}
    except:
        return {'user': None, 'pswd': None, 'error': 'Unauthorized: '+sys.exc_info()[0]}

# our resources
@app.route('/')
def api_root():
    data = [ { 'method': 'GET',
               'description': 'view all db entries',
               'url': '/status' },
             { 'method': 'GET',
               'description': 'view db entry by vm id',
               'url': '/status/vm/<vmid>'},
             { 'method': 'GET',
               'description': 'view db entry by user name',
               'url': '/status/user/<name>'},
             { 'method': 'GET',
               'description': 'nova quota status for type',
               'url': '/status/nova/<type>?verbosity=<min|max>'},
             { 'method': 'GET',
               'description': 'build nginx conf',
               'url': '/conf?port=<int>&ip=<string>' },
             { 'method': 'GET',
               'description': 'view all nova vms',
               'url': '/nova?type=<string>' },
             { 'method': 'POST',
               'description': 'create ipynb vm',
               'url': '/nova?type=<string>&name=<string>' },
             { 'method': 'GET',
               'description': 'view nova vm',
               'url': '/nova/<vmid>?type=<string>' },
             { 'method': 'PUT',
               'description': 'reboot ipynb vm',
               'url': '/nova/<vmid>' },
             { 'method': 'DELETE',
               'description': 'delete ipynb vm',
               'url': '/nova/<vmid>' },
             { 'method': 'POST',
               'description': 'start ipython on vm',
               'url': '/ipython/<vmid>' },
             { 'method': 'PUT',
               'description': 'reboot ipython on vm',
               'url': '/ipython/<vmid>' },
             { 'method': 'DELETE',
               'description': 'stop ipython on vm',
               'url': '/ipython/<vmid>' } ]
    return return_json(data)

@app.route('/status', methods=['GET'])
def api_status_all():
    ipydb = IpyDB(dbc)
    if ipydb.error:
        return return_json(None, 'Service Unavailable: unable to connect to database, %s'%ipydb.error, 503)
    res = ipydb.list()
    ipydb.exit()
    return return_json(res) if res else return_json(None, 'Internal Server Error: no data available', 500)

@app.route('/status/vm/<vmid>', methods=['GET'])
def api_status_vm(vmid):
    ipydb = IpyDB(dbc)
    if ipydb.error:
        return return_json(None, 'Service Unavailable: unable to connect to database, %s'%ipydb.error, 503)
    res = ipydb.get('vm_id', vmid)
    ipydb.exit()
    return return_json(res) if res else return_json(None, 'Internal Server Error: data not available for %s'%vmid, 500)
    
@app.route('/status/user/<name>', methods=['GET'])
def api_status_user(name):
    ipydb = IpyDB(dbc)
    if ipydb.error:
        return return_json(None, 'Service Unavailable: unable to connect to database, %s'%ipydb.error, 503)
    res = ipydb.get('user_name', name)
    ipydb.exit()
    return return_json(res) if res else return_json(None, 'Internal Server Error: data not available for %s'%name, 500)

@app.route('/status/nova/<type>', methods=['GET'])
def api_status_nova(ntype):
    full = True if ('verbosity' in request.args) and (request.args['verbosity'] == 'max') else False
    sect = 'nova-'+ntype
    if not cfg.has_section(sect):
        return return_json(None, 'Bad Request: unknown nova type %s'%ntype, 400)
    ncfg = cfg.items(sect)
    auth = check_auth(request)
    if auth['error']:
        return return_json(None, auth['error'], 401)
    nova = Nova(auth, ncfg["tenant"], ncfg["auth_url"])
    if nova.error:
        return return_json(None, nova.error['msg'], nova.error['status'])
    res = nova.available(full)
    return return_json(res['data']) if res['status'] == 200 else return_json(None, res['msg'], res['status'])

@app.route('/conf', methods=['GET'])
def api_conf():
    pstart = int(cfg.get("ipyno", "pstart"))
    pend = int(cfg.get("ipyno", "pend"))
    if 'port' not in request.args:
        return return_json(None, "Bad Request: missing option 'port'", 400)
    if 'ip' not in request.args:
        return return_json(None, "Bad Request: missing option 'ip'", 400)
    try:
        port = int(request.args['port'])
    except ValueError:
        return return_json(None, "Bad Request: 'port' must be an integer", 400)
    if (port < pstart) or (port > pend):
        return return_json(None, "Bad Request: 'port' must be between %d and %d"%(pstart, pend), 400)
    template_str = open('config/'+cfg.get("proxy", "template")).read()
    new_str = template_str.format(port=port, ip=request.args['ip'], ipy_port=cfg.get("proxy", "ipy_port"))
    return return_json(new_str)
    
@app.route('/nova', methods=['GET', 'POST'])
def api_nova():
    sect = 'nova-'+request.args['type'] if 'type' in request.args else 'nova-ipy'
    if not cfg.has_section(sect):
        return return_json(None, 'Bad Request: unknown nova type %s'%request.args['type'], 400)
    ncfg = cfg.items(sect)
    auth = check_auth(request)
    if auth['error']:
        return return_json(None, auth['error'], 401)
    nova = Nova(auth, ncfg["tenant"], ncfg["auth_url"])
    if nova.error:
        return return_json(None, nova.error['msg'], nova.error['status'])
    if request.method == 'GET':
        res = nova.server()
        return return_json(res['data']) if res['status'] == 200 else return_json(None, res['msg'], res['status'])
    elif request.method == 'POST':
        ipydb = IpyDB(dbc)
        if ipydb.error:
            return return_json(None, 'Service Unavailable: unable to connect to database, %s'%ipydb.error, 503)
        name = request.args['name'] if 'name' in request.args else 'ipynb_'+ipydb.next_val()
        res  = nova.create(name, ncfg["image"], ncfg["flavor"], ncfg["security"], ncfg["vm_key"])
        if res['status'] == 200:
            ipydb.insert(res['data']['id'], res['data']['name'], res['data']['addresses'][0]['addr'], ncfg["vm_key"])
            return return_json(res['data'])
        else:
            return return_json(None, res['msg'], res['status'])
    else:
        return return_json(None, 'Method Not Allowed (%s): %s'%(request.method, request.url), 405)

@app.route('/nova/<vmid>', methods=['GET', 'PUT', 'DELETE'])
def api_nova_server(vmid):
    sect = 'nova-'+request.args['type'] if 'type' in request.args else 'nova-ipy'
    if not cfg.has_section(sect):
        return return_json(None, 'Bad Request: unknown nova type %s'%request.args['type'], 400)
    ncfg = cfg.items(sect)
    auth = check_auth(request)
    if auth['error']:
        return return_json(None, auth['error'], 401)
    nova = Nova(auth, ncfg["tenant"], ncfg["auth_url"])
    if nova.error:
        return return_json(None, nova.error['msg'], nova.error['status'])
    if request.method == 'GET':
        res = nova.server(vmid)
        return return_json(res['data']) if res['status'] == 200 else return_json(None, res['msg'], res['status'])
    elif request.method == 'PUT':
        res = nova.reboot(vmid)
        return return_json(vmid+' is rebooting') if res['status'] == 200 else return_json(None, res['msg'], res['status'])
    elif request.method == 'DELETE':
        ipydb = IpyDB(dbc)
        if ipydb.error:
            return return_json(None, 'Service Unavailable: unable to connect to database, %s'%ipydb.error, 503)
        res = nova.delete(vmid)
        if res['status'] == 200:
            ipydb.delete(vmid)
            return return_json(vmid+' is deleting')
        else:
            return return_json(None, res['msg'], res['status'])
    else:
        return return_json(None, 'Method Not Allowed (%s): %s'%(request.method, request.url), 405)

@app.route('/ipython/<vmid>', methods=['POST', 'PUT', 'DELETE'])
def api_ipy(vmid):
    ipycfg = dict(cfg.items('ipython'))
    ipydb  = IpyDB(dbc)
    sshdir = cfg.get("ipyno", "sshdir")
    if ipydb.error:
        return return_json(None, 'Service Unavailable: unable to connect to database, %s'%ipydb.error, 503)
    vminfo = ipydb.get('vm_id', vmid)
    if request.method == 'POST':
        cmd = 'cd %s; ./%s'%(ipycfg['init_dir'], ipycfg['init_script'])
        res = utils.run_remote_cmd(vminfo['vm_ip'], ipycfg['user'], join(sshdir, vminfo['vm_key']), cmd)
        if res['stderr']:
            return return_json(None, 'Internal Server Error: %s'%res['stderr'], 500)
        else:
            return return_json('started ipython on %s (%s)'%(vminfo['vm_name'], vminfo['vm_id']))
    elif request.method == 'PUT':
        cmd = 'cd %s; ./%s; sleep 1; ./%s'%(ipycfg['run_dir'], ipycfg['stop_script'], ipycfg['start_script'])
        res = utils.run_remote_cmd(vminfo['vm_ip'], ipycfg['user'], join(sshdir, vminfo['vm_key']), cmd)
        if res['stderr']:
            return return_json(None, 'Internal Server Error: %s'%res['stderr'], 500)
        else:
            return return_json('rebooted ipython on %s (%s)'%(vminfo['vm_name'], vminfo['vm_id']))
    elif request.method == 'DELETE':
        cmd = 'cd %s; ./%s'%(ipycfg['run_dir'], ipycfg['stop_script'])
        res = utils.run_remote_cmd(vminfo['vm_ip'], ipycfg['user'], vminfo['vm_key'], cmd)
        if res['stderr']:
            return return_json(None, 'Internal Server Error: %s'%res['stderr'], 500)
        else:
            return return_json('stoped ipython on %s (%s)'%(vminfo['vm_name'], vminfo['vm_id']))

def return_json(data, err=None, status=200):
    obj = { 'data': data,
            'error': err,
            'status': status,
            'timestamp': str(datetime.now()) }
    resp = jsonify(obj)
    resp.status_code = status
    return resp

if __name__ == '__main__':
    app.run('0.0.0.0', int(cfg.get("ipyno", "port")))