#!/usr/bin/env python

import sys
from novaclient.v1_1 import client

class Nova(object):
    def __init__(self, auth, cfg, space='ipy'):
        self.section = "nova-"+space
        self.handle = None
        self.error = None
        if cfg.has_section(self.section):
            try:
                self.handle = client.Client(
                    auth['user'], auth['pswd'],
                    cfg.get(self.section, "tenant"),
                    cfg.get(self.section, "auth_url"),
                    insecure=True )
                test = self.handle.flavors.list()
            except:
                e = sys.exc_info()[0]
                self.error = {'status': e.http_status, 'msg': e.__doc__}
                self.handle = None
        else:
            self.error = {'status': 400, 'msg': "Bad Request: invalid nova type '%s'"%space}
    
    def _server_dict(self, server):
        return { 'created': server.created,
                 'flavor': server.flavor,
                 'id': server.id,
                 'image': server.image['id'],
                 'name': server.name,
                 'addresses': server.addresses['service'],
                 'status': server.status,
                 'updated': server.updated,
                 'user_id': server.user_id,
                 'key_name': server.key_name,
                 'metadata': server.metadata }
    
    def list(self):
        servers = []
        for s in self.handle.servers.list():
            servers.append(self._server_dict(s))
        return servers
    
    def get(self, sid):
        server = self.handle.servers.get(sid)
        return self._server_dict(server)
        
    def create(self, name, cfg):
        image = self.handle.images.get(cfg.get(self.section, "image"))
        flavor = self.handle.flavors.get(cfg.get(self.section, "flavor"))
        security = self.handle.security_groups.get(cfg.get(self.section, "security"))
        server = self.handle.servers.create(
            name, image, flavor,
            security_groups=[security],
            key_name=cfg.get(self.section, "vm_key") )
        return self._server_dict(server)
    
    def delete(self, sid):
        try:
            server = self.handle.servers.get(sid)
            server.delete()
            return None
        except:
            e = sys.exc_info()[0]
            return {'status': e.http_status, 'msg': e.__doc__}
    
    def reboot(self, sid, level='REBOOT_HARD'):
        try:
            server = self.handle.servers.get(sid)
            server.reboot(level)
            return None
        except:
            e = sys.exc_info()[0]
            return {'status': e.http_status, 'msg': e.__doc__}
