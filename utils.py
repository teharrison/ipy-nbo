#!/usr/bin/env python

import sys, re
import requests
import paramiko
from datetime import datetime

def run_remote_cmd(host, user, key, cmd):
    res = {'stderr': None, 'stdout': None}
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, username=user, key_filename=key)
        stdin, stdout, stderr = ssh.exec_command(cmd)
        stdin.close()
        res['stdout'] = stdout.read()
        res['stderr'] = ''.join(filter(lambda x: not x.startswith('zip_safe'), stderr.readlines()))
    except:
        res['stderr'] = sys.exc_info()[0].__doc__
    finally:
        ssh.close()
        return res

def stringify_dt(data):
    if data:
        for k, v in data.iteritems():
            if type(v) is datetime:
                data[k] = str(v)
    return data

def parse_nginx(dbh, text):
    servers = []
    aserver = {}
    text = ''
    for line in text.split('\n'):
        line.strip()
        if line.startswith('server') and aserver:
            aserver['text'] = text
            servers.append(aserver)
            aserver = {}
            text = ''
        elif line.startswith('listen'):
            aserver['port'] = line.split()[1]
        elif line.startswith('proxy_pass'):
            m = re.search(r'http://(.+):(\d+)/', line)
            if m:
                aserver['ip'] = m.group(1)
    aserver['text'] = text
    servers.append(aserver)
    for s in servers:
        data = dbh.get('ip', s['ip'])
        if data and (data['port'] == s['port']):
            s.update(data)
    return servers

def get_oauth(url, token):
    try:
        name = token.split('|')[0].split('=')[1]
    except:
        return {'status': 401, 'error': 'Invalid user and/or token', 'data': None}
    try:
        rget = requests.get(url+'/'+name, headers={'Authorization': 'Globus-Goauthtoken %s'%token})
    except Exception as e:
        return {'status': 504, 'error': 'Unable to connect to OAuth server %s: %s'%(url, e), 'data': None}
    if not (rget.ok and rget.text):
        return {'status': 504, 'error': 'Unable to connect to OAuth server %s: %s'%(url, rget.raise_for_status()), 'data': None}
    data = rget.json
    if not (data and isinstance(data, dict)):
        return {'status': 401, 'error': 'Invalid user and/or token', 'data': None}
    return {'status': 200, 'data': data}
