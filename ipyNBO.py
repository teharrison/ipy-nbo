#!/usr/bin/env python

import sys, datetime
import ConfigParser
import psycopg2, psycopg2.extras
from datetime import datetime
from flask import Flask, request, jsonify, url_for
from nova import Nova

# gloabl variables
app = Flask(__name__)
cfg = ConfigParser.ConfigParser()
dbh = None
nova = {}

# load config
try:
    cfg.read(['config/config.ini'])
except:
    sys.stderr.write("Error: Could not load configuration\n")
    sys.exit(1)

# set up db handle
try:
    dbh = psycopg2.connect(
        host='localhost',
        database=cfg.get("psql", "name"),
        user=cfg.get("psql", "user"),
        password=cfg.get("psql", "password") )
except psycopg2.DatabaseError, e:
    if dbh:
        dbh.rollback()
    sys.stderr.write('Error: %s'%e)
    sys.exit(1)

# nova handels
nova['admin'] = Nova(cfg, 'admin')
nova['ipy'] = Nova(cfg, 'ipy')

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
def not_allowed(error=None):
    msg = 'Internal Server Error: %s'%request.url
    return return_json(None, msg, 500)

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
             { 'method': 'GET',
               'description': 'view nova vm',
               'url': '/nova/<vmid>?type=<string>' },
             { 'method': 'POST',
               'description': 'create ipynb vm',
               'url': '/nova/<vmid>' },
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
    cur = dbh.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM status")
    res = map(lambda x: clean_dt(x), cur.fetchall())
    if res:
        return return_json(res)
    else:
        return return_json(None, 'Internal Server Error: no data available', 500)

@app.route('/view/<vmid>', methods=['GET'])
def api_view(vmid):
    cur = dbh.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM status WHERE vm_id = %s", (vmid,))
    vm = cur.fetchone()
    if vm:
        return return_json(clean_dt(vm))
    else:
        return return_json(None, 'Internal Server Error: data not available for %s'%vmid, 500)
    
@app.route('/user/<name>', methods=['GET'])
def api_user(name):
    cur = dbh.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM status WHERE user_name = %s", (name,))
    usr = cur.fetchone()
    if usr:
        return return_json(clean_dt(usr))
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
    
@app.route('/nova', methods=['GET'])
def api_nova_list():
    space = request.args['type'] if 'type' in request.args else 'admin'
    if space not in nova:
        return return_json(None, "Bad Request: invalid nova type '%s'"%space, 400)
    return return_json(nova[space].list())

@app.route('/nova/<vmid>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def api_nova_server(vmid):
    space = request.args['type'] if 'type' in request.args else 'ipy'
    if space not in nova:
        return return_json(None, "Bad Request: invalid nova type '%s'"%space, 400)
    if request.method == 'GET':
        return return_json(nova[space].view(vmid))
    elif request.method == 'POST':
        success = nova['ipy'].create('ipynb_'+next_val(), cfg, 'ipy')
    elif request.method == 'PUT':
        success = nova[space].reboot(vmid)
    elif request.method == 'DELETE':
        success = nova[space].delete(vmid)

@app.route('/ipython/<vmid>', methods=['POST', 'PUT', 'DELETE'])
def api_ipy(vmid):
    if request.method == 'POST':
        return return_json([request.method, 'start ipython', vmid])
    elif request.method == 'PUT':
        return return_json([request.method, 'reboot ipython', vmid])
    elif request.method == 'DELETE':
        return return_json([request.method, 'stop ipython', vmid])

# helper functions
def next_val():
    cur = dbh.cursor()
    cur.execute("SELECT MAX(_id) FROM status")
    return cur.fetchone()[0] + 1

def clean_dt(data):
    if ('vm_start' in data) and data['vm_start']:
        data['vm_start'] = str(data['vm_start'])
    if ('vm_last_access' in data) and data['vm_last_access']:
        data['vm_last_access'] = str(data['vm_last_access'])
    return data

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