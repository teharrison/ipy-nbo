#!/usr/bin/env python

import sys, re
import utils
from os.path import basename

class Proxy(object):
    """config values
    port=7051
    pstart=50001
    pend=60000
    user=ubuntu
    host=0.0.0.0
    external=0.0.0.0
    cfg_dir=/etc/nginx/sites-available
    cfg_file=default
    template=nginx.template
    """
    def __init__(self, config, key):
        self.key = key
        for k, v in config.iteritems():
            setattr(self, k, v)

    def _get_config(self, user):
        cmd = "cat %s/%s.server"%(self.cfg_dir, user)
        res = utils.run_remote_cmd(self.host, self.user, self.key, cmd)
        if res['stderr']:
            return {'status': 500, 'error': 'Internal Server Error: '+res['stderr'], 'data': None}
        text = res['stdout']
        data = {}
        for line in text.split('\n'):
            line.strip()
            if line.startswith('listen'):
                data['port'] = line.split()[1]
            if line.startswith('proxy_pass'):
                m = re.search(r'http://(.+):(\d+)/', line)
                if m:
                    data['ip'] = m.group(1)
        if not data:
            return {'status': 500, 'error': 'Internal Server Error: invalid proxy config for %s'%user, 'data': None}
        data['user'] = user
        data['config'] = text
        return {'status': 200, 'data': data}

    def _list_users(self):
        cmd = "ls %s/*.server"%(self.cfg_dir)
        res = utils.run_remote_cmd(self.host, self.user, self.key, cmd)
        if res['stderr']:
            return {'status': 500, 'error': 'Internal Server Error: '+res['stderr'], 'data': None}
        try:
            files = res['stdout'].strip().split('\n')
            users = map(lambda x: basename(x).split('.')[0], files)
            return {'status': 200, 'data': users}
        except:
            return {'status': 500, 'error': 'Internal Server Error: '+sys.exc_info()[0].__doc__, 'data': None}

    def _relaod_config(self):
        cmd = "sudo cat %s/*.server > %s/%s; sudo /etc/init.d/nginx reload"%(self.cfg_dir, self.cfg_dir, self.cfg_file)
        res = utils.run_remote_cmd(self.host, self.user, self.key, cmd)
        if res['stderr']:
            return {'status': 500, 'error': 'Internal Server Error: '+res['stderr'], 'data': None}
        return {'status': 200, 'data': 'success'}

    def get_server(self, user=None):
        if user:
            return self._get_config(user)
        users = self._list_users()
        if users['status'] != 200:
            return users
        servers = []
        for u in users['data']:
            conf = self._get_config(u)
            if conf['status'] == 200:
                servers.append(conf['data'])
        return {'status': 200, 'data': servers}

    def add_server(self, user, ip, port):
        server_cfg = self.template.format(port=port, ip=ip, ipy_port=self.pport)
        cmd = 'sudo echo "%s" > %s/%s.server'%(server_cfg, self.cfg_dir, user)
        res = utils.run_remote_cmd(self.host, self.user, self.key, cmd)
        if res['stderr']:
            return {'status': 500, 'error': 'Internal Server Error: '+res['stderr'], 'data': None}
        res = self._relaod_config();
        if res['status'] != 200:
            return res
        return {'status': 200, 'data': {'user': user, 'ip': ip, 'port': ip,'config': server_cfg}}
    
    def remove_server(self, user):
        cmd = "sudo rm -f %s/%s.server"%(self.cfg_dir, user)
        res = utils.run_remote_cmd(self.host, self.user, self.key, cmd)
        if res['stderr']:
            return {'status': 500, 'error': 'Internal Server Error: '+res['stderr'], 'data': None}
        return {'status': 200, 'data': 'success'}
