#!/usr/bin/env python

import sys
from novaclient.v1_1 import client

class Nova(object):
    def __init__(self, cfg, space='ipy'):
        self.handle = None
        try:
            section = "nova-" + space
            self.handle = client.Client(
                cfg.get(section, "user"),
                cfg.get(section, "pwd"),
                cfg.get(section, "tenant"),
                cfg.get(section, "auth_url"),
                insecure=True )
        except:
            sys.stderr.write("Error: Could not connect to %s openstack\n"%space)
    
    def _server_dict(self, server):
        return { 'created': server.created,
                 'flavor': server.flavor,
                 'id': server.id,
                 'image': server.image['id'],
                 'name': server.name,
                 'addresses': server.addresses,
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
    
    def view(self, sid):
        server = self.handle.servers.get(sid)
        return self._server_dict(server)
        
    def create(self, name, cfg, space):
        section = "nova-" + space
        try:
            image = self.handle.images.get(cfg.get(section, "image"))
            flavor = self.handle.flavors.get(cfg.get(section, "flavor"))
            security = self.handle.security_groups.get(cfg.get(section, "security"))
            self.handle.servers.create(
                name, image, flavor,
                security_groups=[security],
                key_name=cfg.get(section, "vm_key") )
            return True
        except:
            return False
    
    def delete(self, sid):
        try:
            server = self.handle.servers.get(sid)
            server.delete()
            return True
        except:
            return False
    
    def reboot(self, sid, level='REBOOT_HARD'):
        try:
            server = self.handle.servers.get(sid)
            server.reboot(level)
            return True
        except:
            return False
