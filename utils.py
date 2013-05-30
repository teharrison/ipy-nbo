#!/usr/bin/env python

import sys
import paramiko
from datetime import datetime

def run_remote_cmd(host, user, key, cmd):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, username=user, key_filename=key)
        stdin, stdout, stderr = ssh.exec_command(cmd)
        return {'stderr': stderr.read(), 'stdout': stdout.read()}
    except:
        e = sys.exc_info()[0]
        return {'stderr': e.__doc__, 'stdout': None}
    finally:
        ssh.close()

def stringify_dt(data):
    if data:
        for k, v in data.iteritems():
            if type(v) is datetime:
                data[k] = str(v)
    return data
