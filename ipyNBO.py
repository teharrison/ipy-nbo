#!/usr/bin/env python
 
import sys, time, base64
import requests
import datetime
import schedule
import ConfigParser
from optparse import OptionParser
from pprint import pprint
from dateutil import parser
from daemon import Daemon

class IpyDaemon(Daemon):
    def __init__(self, config=None, section=None):
        """
        override parent __init__, then run it at end
        """
        self.conf = config
        self.sect = section
        prefix = self.conf.get(self.sect, 'log')+'/'+self.sect
        Daemon.__init__(self, prefix+'.pid', stdout=prefix+'.log', stderr=prefix+'.log')
    
    def foreground(self, now=None):
        """
        Run daemon in forground - usefull for debugging
        """
        self.checkpid()
        self.run(now=now)
    
    def run(self, now=None):
        if now == 'delete':
            pprint( self.delete_inactive() )
            return
        if now == 'cleanup':
            pprint( self.cleanup() )
            return
        if now == 'boot':
            pprint( self.boot_min() )
            return
        if now == 'status':
            pprint( self.status() )
            return
        sched = schedule.Scheduler()
        sched.every().hour.do(self.status)
        sched.every().day.at("00:15").do(self.delete_inactive)
        sched.every().day.at("01:15").do(self.cleanup)
        sched.every().day.at("02:15").do(self.boot_min)
        while True:
            sched.run_pending()
            time.sleep(1)

    def status(self):
        """
        Wrapper for _update_status and _get_status
        """
        self._update_status()
        time.sleep(60)
        self._get_status()

    def _log(self, method, path, state, msg):
        """
        log message formater
        """
        this_pid = self.checkpid(False)
        time_now = str(datetime.datetime.now())
        if state == 'ERROR':
            sys.stderr.write("%s [%d] [%s] [%s] [%s] %s"%(time_now, this_pid, state, method, path, msg))
        else:
            sys.stdout.write("%s [%d] [%s] [%s] [%s] %s"%(time_now, this_pid, state, method, path, msg))

    def _update_status(self):
        """
        Update VM openstack status
        """
        data, error = self.call_api('PUT', 'status', auth='psql')
        if error:
            self._log('PUT', '/status', 'ERROR', error)
            return None
        self._log('PUT', '/status', 'INFO', 'updated VM status via nova')
        return data

    def _get_status(self):
        """
        Retrieve VM status - both openstack and user
        """
        data, error = self.call_api('GET', 'status', auth='psql')
        if error:
            self._log('GET', '/status', 'ERROR', error)
            return None
        active = 0
        users  = 0
        for vm in data:
            if vm['status'] == 'ACTIVE':
                active += 1
            if vm['user']:
                users += 1
        self._log('GET', '/status', 'INFO', '%d VMs running'%active)
        if active != len(data):
            self._log('GET', '/status', 'WARNING', 'only %d of %d VMs ACTIVE'%(active, len(data)))
        self._log('GET', '/status', 'INFO', '%d of %d VMs have users'%(users, len(data)))
        return data
    
    def _delete_vm(self, vm, nova=False):
        """
        Delete VM from DB. Return if worked.
        If has user, delete from proxy.
        If 'nova' is true, delete from openstack
        """
        # delete user from proxy
        if vm['user']:
            deluser, error = self.call_api('DELETE', 'proxy', params={'user': vm['user']}, auth='nova-admin')
            if error:
                self._log('DELETE', '/proxy', 'ERROR', error)
            else:
                self._log('DELETE', '/proxy', 'INFO', 'user %s removed from proxy'%vm['user'])
        # delete vm from db and openstack
        if nova:
            delvm, error = self.call_api('DELETE', 'nova/'+vm['id'], auth='nova-pool')
            if error:
                self._log('DELETE', '/nova/'+vm['id'], 'ERROR', error)
                return None
            else:
                self._log('DELETE', '/nova/'+vm['id'], 'INFO', 'VM %s removed from DB and openstack'%vm['id'])
                return delvm
        # only delete vm from db
        else:
            delvm, error = self.call_api('DELETE', 'status/vm/'+vm['id'], auth='psql')
            if error:
                self._log('DELETE', '/status/vm/'+vm['id'], 'ERROR', error)
                return None
            else:
                self._log('DELETE', '/status/vm/'+vm['id'], 'INFO', 'VM %s removed from DB'%vm['id'])
                return delvm
    
    def cleanup(self, hard=False):
        """
        Remove VMs from db not in openstack (UNKNOWN status).
        If 'hard' is True, remove all not in 'ACTIVE' status.
        """
        data = self._get_status()
        if not data:
            return None
        cleaned = []
        for vm in data:
            if vm['status'] == 'UNKNOWN':
                self._log('GET', '/status', 'WARNING', 'VM %s missing from openstack - deleting'%vm['id'])
                delvm = self._delete_vm(vm)
                if delvm:
                    cleaned.append(delvm)
            elif hard and (vm['status'] != 'ACTIVE'):
                delvm = self._delete_vm(vm, True)
                if delvm:
                    cleaned.append(delvm)
        return cleaned
    
    def delete_inactive(self):
        """
        remove VMs from db and openstack if inactive
        NOTE: in this version 'inactive' means older then 72 hours
        """
        data = self._get_status()
        if not data:
            return None
        deleted = []
        now = datetime.datetime.now()
        for vm in data:
            start = parser.parse(vm['start'])
            delta = now - start
            hours = delta.total_seconds() / (60 * 60)
            if hours > self.conf.get(self.sect, 'inactive'):
                delvm = self._delete_vm(vm, True)
                if delvm:
                    deleted.append(delvm)
        return deleted
    
    def boot_min(self):
        """
        Boot VMs if current spawned less than minimum
        """
        data = self._get_status()
        if not data:
            return None
        min_vm = self.conf.get(self.sect, 'min_vm')
        booted = []
        if min_vm > len(data):
            self._log('GET', '/status', 'WARNING', 'VM count (%d) less then minimum (%s) - booting more'%(len(data), min_vm))
            for _ in range(min_vm - len(data)):
                vm, error = self.call_api('POST', 'nova', auth='nova-pool')
                if error:
                    self._log('POST', '/nova', 'ERROR', error)
                else:
                    booted.append(vm)
                    self._log('POST', '/nova', 'INFO', 'Launched VM '+vm['id'])
                time.sleep(60)
        return booted
    
    def call_api(self, method, resource, params=None, auth=None):
        """
        given method, resource, params, auth - return tuple: data, error
        """
        kwargs = {}
        if auth:
            code = base64.b64encode(self.conf.get(auth, 'user')+':'+self.conf.get(auth, 'password'))
            kwargs['headers'] = {'Authorization': 'Basic '+code}
        if params:
            kwargs['params'] = params
        try:
            url = self.conf.get(self.sect, 'api_url')+':'+self.conf.get(self.sect, 'port')+'/'+resource
            if kwargs:
                result = requests.request(method, url, **kwargs)
            else:
                result = requests.request(method, url)
        except Exception as e:
            return None, "Unable to connect to API server: "+e
        if not (result.ok and result.text):
            return None, "Unable to connect to API server: "+e
        rj = result.json
        if not (rj and isinstance(rj, dict)):
            return None, "Return data not valid JSON format"
        if rj['error']:
            return None, "%s (%d)"%(rj['error'], rj['status'])
        return rj['data'], None

def get_config(cfile):
    try:
        cfg = ConfigParser.ConfigParser()
        cfg.read([cfile])
        return cfg
    except:
        sys.stderr.write("Error: Could not load configuration\n")
        sys.exit(1)

usage = "usage: %prog [options] start|stop|restart|foreground\n"
def main(args):
    global CONF, SECT
    parser = OptionParser(usage=usage)
    parser.add_option("-c", "--config", dest="config", default='config/config.ini', help="Location of config file")
    parser.add_option("-s", "--section", dest="section", default='ipyno', help="Config section to use")
    parser.add_option("-t", "--section", dest="test", default='status', help="test a daemon function: delete|cleanup|boot|status")
    
    (opts, args) = parser.parse_args()
    if not ((len(args) == 1) and (args[0] in ['stop','start','restart','foreground'])):
        sys.stderr.write(usage)
        return 2

    config = get_config(opts.config)
    daemon = IpyDaemon(config=config, section=opts.section)
    if 'start' == args[0]:
        daemon.start()
    elif 'stop' == args[0]:
        daemon.stop()
    elif 'restart' == args[0]:
        daemon.restart()
    elif 'foreground' == args[0]:
        daemon.foreground(now=opts.test)
    else:
        sys.stderr.write("[error] unknown command '%s'\n"%args[0])
        return 2
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))