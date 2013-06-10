#!/usr/bin/env python

import sys, os, time, atexit
from signal import SIGTERM

class Daemon:
    """
    A generic daemon class.
    Usage: subclass the Daemon class and override the run() method
    """
    def __init__(self, pidfile, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        self.stdin   = stdin
        self.stdout  = stdout
        self.stderr  = stderr
        self.pidfile = pidfile
    
    def daemonize(self):
        """
        Do UNIX double-fork magic
        """
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError, e:
            sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)
                
        # decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)
        
        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                sys.exit(0)
        except OSError, e:
            sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)
                
        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = file(self.stdin, 'r')
        so = file(self.stdout, 'a+')
        se = file(self.stderr, 'a+', 0)
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())
                
        # write pidfile
        atexit.register(self.delpid)
        pid = str(os.getpid())
        file(self.pidfile,'w+').write("%s\n" % pid)
    
    def delpid(self):
        os.remove(self.pidfile)
    
    def checkpid(self, error=True):
        """
        Check for a pidfile to see if the daemon already runs
        if 'error' is True, exit if pid is missing
        """
        try:
            pf = file(self.pidfile,'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None
        if pid:
            sys.stderr.write("pid file %s already exists. Daemon already running as %d\n"%(self.pidfile, pid))
            if error:
                sys.exit(1)
        return pid
    
    def foreground(self):
        """
        Run daemon in forground - usefull for debugging
        """
        self.checkpid()
        self.run()
    
    def start(self):
        """
        Start the daemon
        """
        self.checkpid()
        self.daemonize()
        self.run()
    
    def stop(self):
        """
        Stop the daemon
        """
        # Get the pid from the pidfile if exists
        pid = self.checkpid(False)
        if not pid:
            return # do nothing if not running
                
        # Try killing the daemon process
        try:
            while 1:
                os.kill(pid, SIGTERM)
                time.sleep(0.1)
        except OSError, err:
            err = str(err)
            if err.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                print str(err)
                sys.exit(1)
    
    def restart(self):
        """
        Restart the daemon
        """
        self.stop()
        self.start()
    
    def run(self):
        """
        Override this method when you subclass Daemon.
        """
