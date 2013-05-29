#!/usr/bin/env python

import sys
from novaclient.v1_1 import client

class Nova(object):
    def __init__(self, auth, tenant, url):
        self.handle = None
        self.error  = None
        self.tenant = None
        try:
            self.handle = client.Client(auth['user'], auth['pswd'], tenant, url, insecure=True)
            self.tenant = self.handle.servers.list()[0].tenant_id
        except:
            e = sys.exc_info()[0]
            self.error = {'status': e.http_status, 'msg': e.__doc__, 'data': None}
            self.handle = None
    
    def _build_error(self, e):
        if hasattr(e, 'http_status'):
            return {'status': e.http_status, 'msg': e.__doc__, 'data': None}
        else:
            return {'status': 500, 'msg': 'Internal Server Error: '+e.__doc__, 'data': None}
    
    # server object to dict
    def _server_dict(self, server):
        return { 'created': server.created,
                 'flavor': server.flavor['id'] if 'id' in server.flavor else None,
                 'id': server.id,
                 'image': server.image['id'] if 'id' in server.image else None,
                 'name': server.name,
                 'addresses': server.addresses['service'] if 'service' in server.addresses else [],
                 'status': server.status,
                 'updated': server.updated,
                 'user': server.user_id,
                 'tenant': server.tenant_id,
                 'key_name': server.key_name,
                 'metadata': server.metadata }
    
    # flavor object to dict
    def _flavor_dict(self, flavor):
        return { 'id': flavor.id,
                 'name': flavor.name,
                 'vcpus': flavor.vcpus,
                 'disk': flavor.disk,
                 'memory': flavor.ram,
                 'ephemeral': getattr(flavor, 'OS-FLV-EXT-DATA:ephemeral') }
    
    # get server by id or list of all
    def server(self, sid=None):
        try:
            data = None
            if sid:
                data = self._server_dict(self.handle.servers.get(sid))
            else:
                data = []
                for s in self.handle.servers.list():
                    data.append(self._server_dict(s))
            return {'status': 200, 'data': data}
        except:
            return self._build_error(sys.exc_info()[0])
    
    # get flavor by id or list of all
    def flavor(self, fid=None):
        try:
            data = None
            if fid:
                data = self._flavor_dict(self.handle.flavors.get(fid))
            else:
                data = []
                for f in self.handle.flavors.list():
                    data.append(self._flavor_dict(f))
            return {'status': 200, 'data': data}
        except:
            return self._build_error(sys.exc_info()[0])
            
    # get quota for resources
    def quota(self):
        try:
            quotas = self.handle.quotas.get(self.tenant)
            data = { 'instances': quotas.instances,
                     'vcpus': quotas.cores,
                     'disk': quotas.gigabytes,
                     'memory': quotas.ram,
                     'floating_ips': quotas.floating_ips,
                     'volumes': quotas.volumes,
                     'id': self.tenant }
            return {'status': 200, 'data': data}
        except:
            return self._build_error(sys.exc_info()[0])
    
    # get currently used resources
    def usage(self):
        servers = self.server()
        flavors = self.flavor()
        if servers['status'] != 200:
            return servers
        if flavors['status'] != 200:
            return flavors
        current = { 'instances': 0,
                    'vcpus': 0,
                    'disk': 0,
                    'memory': 0,
                    'floating_ips': 0 }
        try:
            fmap = dict([(f['id'], f) for f in flavors])
            for s in servers['data']:
                if s['flavor'] not in fmap:
                    continue
                a = len(s['addresses'])
                f = fmap[s['flavor']]
                current['instances'] += 1
                current['vcpus'] += f['vcpus']
                current['disk'] += f['disk'] + f['ephemeral']
                current['memory'] += f['memory']
                if a > 1:
                    current['floating_ips'] += a - 1
            return {'status': 200, 'data': current}
        except:
            return self._build_error(sys.exc_info()[0])
                
    # get available resources
    def available(self, full=False):
        quota = self.quota()
        usage = self.usage()
        if quota['status'] != 200:
            return quota
        if usage['status'] != 200:
            return usage
        curr = { 'instances': quota['data']['instances'] - usage['data']['instances'],
                 'vcpus': quota['data']['vcpus'] - usage['data']['vcpus'],
                 'disk': quota['data']['disk'] - usage['data']['disk'],
                 'memory': quota['data']['memory'] - usage['data']['memory'],
                 'floating_ips': quota['data']['floating_ips'] - usage['data']['floating_ips'] }
        data = {'quota': quota['data'], 'used': usage['data'], 'free': curr} if full else curr
        return {'status': 200, 'data': data}
    
    # create server with options
    def create(self, name, image_id, flavor_id, security_id, key_name):
        try:
            image = self.handle.images.get(image_id)
            flavor = self.handle.flavors.get(flavor_id)
            security = self.handle.security_groups.get(security_id)
            server = self.handle.servers.create(
                name, image, flavor,
                security_groups=[security],
                key_name=key_name )
            return {'status': 200, 'data': self._server_dict(server)}
        except:
            return self._build_error(sys.exc_info()[0])
    
    # delete server
    def delete(self, sid):
        try:
            server = self.handle.servers.get(sid)
            server.delete()
            return {'status': 200, 'data': None}
        except:
            return self._build_error(sys.exc_info()[0])
    
    # reboot server
    def reboot(self, sid, level='REBOOT_HARD'):
        try:
            server = self.handle.servers.get(sid)
            server.reboot(level)
            return {'status': 200, 'data': None}
        except:
            return self._build_error(sys.exc_info()[0])
