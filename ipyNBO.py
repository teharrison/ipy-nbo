#!/usr/bin/env python

import sys, base64
import ConfigParser
from datetime import datetime
from flask import Flask, request, jsonify, url_for
from nova import Nova
from ipydb import IpyDB

# gloabl variables
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
    msg = 'Not Found: %s'%request.url
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
               'url': '/view' },
             { 'method': 'GET',
               'description': 'view db entry by vm id',
               'url': '/view/<vmid>'},
             { 'method': 'GET',
               'description': 'view db entry by user name',
               'url': '/view/<name>'},
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

@app.route('/view', methods=['GET'])
def api_views():
    ipydb = IpyDB(cfg)
    if ipydb.error:
        return return_json(None, 'Service Unavailable: unable to connect to database, %s'%ipydb.error, 503)
    res = ipydb.list()
    ipydb.exit()
    if res:
        return return_json(res)
    else:
        return return_json(None, 'Internal Server Error: no data available', 500)

@app.route('/view/<vmid>', methods=['GET'])
def api_view(vmid):
    ipydb = IpyDB(cfg)
    if ipydb.error:
        return return_json(None, 'Service Unavailable: unable to connect to database, %s'%ipydb.error, 503)
    res = ipydb.get('vm_id', vmid)
    ipydb.exit()
    if res:
        return return_json(res)
    else:
        return return_json(None, 'Internal Server Error: data not available for %s'%vmid, 500)
    
@app.route('/user/<name>', methods=['GET'])
def api_user(name):
    ipydb = IpyDB(cfg)
    if ipydb.error:
        return return_json(None, 'Service Unavailable: unable to connect to database, %s'%ipydb.error, 503)
    res = ipydb.get('user_name', name)
    ipydb.exit()
    if res:
        return return_json(res)
    else:
        return return_json(None, 'Internal Server Error: data not available for %s'%name, 500)
        
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
    space = request.args['type'] if 'type' in request.args else 'ipy'
    auth = check_auth(request)
    if auth['error']:
        return return_json(None, auth['error'], 401)
    nova = Nova(auth, cfg, space)
    if nova.error:
        return return_json(None, nova.error['msg'], nova.error['status'])
    if request.method == 'GET':
        return return_json(nova.list())
    elif request.method == 'POST':
        ipydb = IpyDB(cfg)
        if ipydb.error:
            return return_json(None, 'Service Unavailable: unable to connect to database, %s'%ipydb.error, 503)
        name = request.args['name'] if 'name' in request.args else 'ipynb_'+ipydb.next_val()
        new = nova.create(name, cfg)
        if new:
            ipydb.insert(new['id'], new['name'], new['addresses'][0]['addr'])
            return return_json(new)
        else:
            return return_json(None, 'Internal Server Error: unable to create new VM', 500)
    else:
        return return_json(None, 'Method Not Allowed (%s): %s'%(request.method, request.url), 405)

@app.route('/nova/<vmid>', methods=['GET', 'PUT', 'DELETE'])
def api_nova_server(vmid):
    space = request.args['type'] if 'type' in request.args else 'ipy'
    auth = check_auth(request)
    if auth['error']:
        return return_json(None, auth['error'], 401)
    nova = Nova(auth, cfg, space)
    if nova.error:
        return return_json(None, nova.error['msg'], nova.error['status'])
    if request.method == 'GET':
        return return_json(nova.get(vmid))
    elif request.method == 'PUT':
        error = nova.reboot(vmid)
        if error:
            return return_json(None, error['msg'], error['status'])
        else:
            return return_json(vmid+' is rebooting')
    elif request.method == 'DELETE':
        ipydb = IpyDB(cfg)
        if ipydb.error:
            return return_json(None, 'Service Unavailable: unable to connect to database, %s'%ipydb.error, 503)
        error = nova.delete(vmid)
        if error:
            return return_json(None, error['msg'], error['status'])
        else:
            ipydb.delete(vmid)
            return return_json(vmid+' is deleting')
    else:
        return return_json(None, 'Method Not Allowed (%s): %s'%(request.method, request.url), 405)

@app.route('/ipython/<vmid>', methods=['POST', 'PUT', 'DELETE'])
def api_ipy(vmid):
    if request.method == 'POST':
        return return_json([request.method, 'start ipython', vmid])
    elif request.method == 'PUT':
        return return_json([request.method, 'reboot ipython', vmid])
    elif request.method == 'DELETE':
        return return_json([request.method, 'stop ipython', vmid])

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