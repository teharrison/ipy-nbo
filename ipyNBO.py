#!/usr/bin/env python
 
import sys, time, base64
import requests, json
import schedule
import ConfigParser
from daemon import Daemon

CONF = None
SECT = None

class MyDaemon(Daemon):
    def run(self):
        sched = Scheduler()
        sched.every(5).minutes.do(jobA)
        sched.every().hour.do(jobB)
        sched.every().day.at("4:30").do(jobC)
        while True:
            sched.run_pending()
            time.sleep(1)

def jobA():
    print "I am A"
    
def jobB():
    print "I am B"

def jobC():
    print "I am C"

def get_api(self, resource, params=None, auth=None):
    kwargs = {}
    if auth:
        code = base64.b64encode(CONF.get(auth, 'user')+':'+CONF.get(auth, 'password'))
        kwargs['headers'] = {'Authorization': 'Basic '+code}
    if params:
        kwargs['params'] = params
    url = CONF.get(SECT, 'api_url')+':'+CONF.get(SECT, 'port')+'/'+resource
    try:
        url = CONF.get(SECT, 'api_url')+':'+CONF.get(SECT, 'port')+'/'+resource
        if kwargs:
            rget = requests.get(url, **self.kwargs)
        else:
            rget = requests.get(url)
    except Exception as e:
        return "[error] Unable to connect to API server %s: %s"%(CONF.get(SECT, 'api_url'), e)
    if not (rget.ok and rget.text):
        return "[error] Unable to connect to API server %s: %s"%(CONF.get(SECT, 'api_url'), e)
    rj = rget.json
    if not (rj and isinstance(rj, dict)):
        return "[error] Return data not valid JSON format"
    if rj['error']:
        return "[error] %s (%d)"%(rj['error'], rj['status'])
    return rj['data']

def get_config(cfile):
    try:
        cfg = ConfigParser.ConfigParser()
        cfg.read([cfile])
        return cfg
    except:
        sys.stderr.write("Error: Could not load configuration\n")
        sys.exit(1)

usage = "usage: %prog [options] start|stop|restart\n" + __doc__
def main(args):
    global CONF, SECT
    parser = OptionParser(usage=usage)
    parser.add_option("-n", "--num", dest="num", default=0, type="int", help="Minimum number of VMs to keep running")
    parser.add_option("-c", "--config", dest="config", default='config/config.ini', help="Location of config file")
    parser.add_option("-s", "--section", dest="section", default='ipyno', help="Config section to use")
    
    (opts, args) = parser.parse_args()
    if not ((len(args) == 1) and (args[0] in ['stop','start','restart'])):
        sys.stderr.write(usage)
        return 2

    SECT = opts.section
    CONF = get_config(opts.config)
    if not opts.num:
        opts.num = CONF.get(opts.sect, 'min_vm')
    
    prefix = CONF.get(SECT, 'log')+'/'+SECT
    daemon = MyDaemon(prefix+'.pid', stdout=prefix+'.out', stderr=prefix+'.err')
    if 'start' == args[0]:
        daemon.start()
    elif 'stop' == args[0]:
        daemon.stop()
    elif 'restart' == args[0]:
        daemon.restart()
    else:
        sys.stderr.write("[error] unknown command '%s'\n"%args[0])
        return 2
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))