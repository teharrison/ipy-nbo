#!/usr/bin/env python
 
import sys, time, base64
import requests, json
import schedule
import ConfigParser
from datetime import datetime
from daemon import Daemon

class IpyDaemon(Daemon):
    def __init__(self, config=None, section=None):
        """
        override parent __init__, then run it at end
        """
        self.conf = config
        self.sect = section
        prefix = self.conf.get(self.sect, 'log')+'/'+self.sect
        Daemon.__init__(self, prefix+'.pid', stdout=prefix+'.out', stderr=prefix+'.err')
    
    def run(self):
        sched = Scheduler()
        sched.every(10).minutes.do(self.get_status)
        sched.every().hour.do(self.update_status)
        sched.every().day.at("4:30").do(self.boot_min)
        while True:
            sched.run_pending()
            time.sleep(1)

    def get_status(self):
        data, error, url = self.call_api('GET', 'status', auth='psql')
        if error:
            sys.stderr.write("%s [%s] [ERROR] [%d] %s"%(str(datetime.now()), url, self.checkpid(False), error))
        active = 0
        users  = 0
        for vm in data:
            if vm['status'] == 'ACTIVE':
                active += 1
            if vm['user']:
                users += 1
        sys.stdout.write("%s [%s] [INFO] [%d] %d VMs running"%(str(datetime.now()), url, self.checkpid(False), active))
        if active != len(data):
            sys.stdout.write("%s [%s] [WARNING] [%d] only %d of %d VMs ACTIVE"%(str(datetime.now()), url, self.checkpid(False), active, len(data)))
        sys.stdout.write("%s [%s] [INFO] [%d] %d of %d VMs have users"%(str(datetime.now()), url, self.checkpid(False), users, len(data)))
    
    def update_status(self):
        data, error, url = self.call_api('PUT', 'status', auth='psql')
        if error:
            sys.stderr.write("%s [%s] [ERROR] [%d] %s"%(str(datetime.now()), url, self.checkpid(False), error))
        sys.stdout.write("%s [%s] [INFO] [%d] updated VM status via nova"%(str(datetime.now()), url, self.checkpid(False)))
    
    def boot_min(self):
        data, error, url = self.call_api('GET', 'status', auth='psql')
        return None
    
    def call_api(self, method, resource, params=None, auth=None):
        """
        given method, esource, params, auth - return tuple: data, error, url
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
                result = requests.request(method, url, **self.kwargs)
            else:
                result = requests.request(method, url)
        except Exception as e:
            return None, "Unable to connect to API server: "+e, url
        if not (result.ok and result.text):
            return None, "Unable to connect to API server: "+e, url
        rj = result.json
        if not (rj and isinstance(rj, dict)):
            return None, "Return data not valid JSON format", url
        if rj['error']:
            return None, "%s (%d)"%(rj['error'], rj['status']), url
        return rj['data'], None, url

def get_config(cfile):
    try:
        cfg = ConfigParser.ConfigParser()
        cfg.read([cfile])
        return cfg
    except:
        sys.stderr.write("Error: Could not load configuration\n")
        sys.exit(1)

usage = "usage: %prog [options] start|stop|restart|foreground\n" + __doc__
def main(args):
    global CONF, SECT
    parser = OptionParser(usage=usage)
    parser.add_option("-c", "--config", dest="config", default='config/config.ini', help="Location of config file")
    parser.add_option("-s", "--section", dest="section", default='ipyno', help="Config section to use")
    
    (opts, args) = parser.parse_args()
    if not ((len(args) == 1) and (args[0] in ['stop','start','restart'])):
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
        daemon.foreground()
    else:
        sys.stderr.write("[error] unknown command '%s'\n"%args[0])
        return 2
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))