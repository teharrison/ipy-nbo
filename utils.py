#!/usr/bin/env python

import sys
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
