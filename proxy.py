#!/usr/bin/env python

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
        for line in text.split('\n'):
            line.strip()
            if line.startswith('listen'):
                data['port'] = line.split()[1]
            if line.startswith('proxy_pass'):
                m = re.search(r'http://(.+):(\d+)/', line)
                if m:
                    data['ip'] = m.group(1)
        if data:
            data['user'] = user
            data['text'] = text
            return {'status': 200, 'data': data}
        else:
            return {'status': 500, 'error': 'Internal Server Error: invalid proxy config for %s'%user, 'data': None}

    def _list_users(self):
        cmd = "ls %s/*.server"%(self.cfg_dir, user)
        res = utils.run_remote_cmd(self.host, self.user, self.key, cmd)
        if res['stderr']:
            return {'status': 500, 'error': 'Internal Server Error: '+res['stderr'], 'data': None}
        try:
            files = res['stdout'].strip().split('\n')
            users = map(lambda x: basename(x).split('.')[0], files)
            return {'status': 200, 'data': users}
        except:
            return {'status': 500, 'error': 'Internal Server Error: '+sys.exc_info()[0].__doc__, 'data': None}

    def server(self, user=None):
        if user:
            return self._get_config(user)
        users = self._list_users()
        if users['status'] != 200:
            return users
        servers = []
        for u in users:
            cfg = self._get_config(u)
            if cfg['status'] == 200:
                servers.append(cfg['data'])
        return {'status': 200, 'data': servers}

    def add_server(self, ip, port):
        server_cfg = self.template.format(port=port, ip=ip, ipy_port=self.pport)
        cmd = 'sudo echo "%s" >> %s; sudo /etc/init.d/nginx reload'%(server_cfg, self.nginx)
        res = utils.run_remote_cmd(self.host, self.user, self.key, cmd)
        if res['stderr']:
            return {'status': 500, 'error': 'Internal Server Error: '+res['stderr'], 'data': None}
        else:
            return {'status': 200, 'data': server_cfg}
    
    def remove_server(self, ip):
        