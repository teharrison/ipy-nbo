#!/usr/bin/env python

import random
import psycopg2, psycopg2.extras
import utils
from datetime import datetime

class IpyDB(object):
    def __init__(self, params):
        self.handle = None
        self.error = None
        try:
            self.handle = psycopg2.connect(**params)
        except psycopg2.DatabaseError, e:
            if self.handle:
                self.handle.rollback()
                self.handle.close()
                self.handle = None
            self.error = e

    def cursor(self, keys=False):
        if keys:
            return self.handle.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            return self.handle.cursor()
    
    def drop(self, table):
        cur = self.cursor()
        cur.execute("DROP TABLE IF EXISTS "+table)
        cur.close()
    
    def create(self):
        cur = self.cursor()
        cur.execute(
            """CREATE TABLE status (
                _id SERIAL UNIQUE PRIMARY KEY,
                id uuid UNIQUE NOT NULL,
                name text NOT NULL,
                ip inet NOT NULL,
                key text NOT NULL,
                start TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL,
                last_status TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                ipy_on BOOLEAN NOT NULL,
                reserved BOOLEAN NOT NULL,
                last_access TIMESTAMP,
                user UNIQUE TEXT,
                port UNIQUE INTEGER
            );""")
        cur.execute("CREATE INDEX status_vm ON status (id);")
        cur.execute("CREATE INDEX status_ip ON status (ip);")
        cur.execute("CREATE INDEX status_user ON status (user);")
        cur.execute("CREATE INDEX status_status ON status (status);")
        cur.close()
    
    def list(self):
        cur = self.cursor(True)
        cur.execute("SELECT * FROM status")
        res = map(lambda x: utils.stringify_dt(x), cur.fetchall())
        cur.close()
        return res
        
    def get(self, column, value):
        cur = self.cursor(True)
        cur.execute("SELECT * FROM status WHERE "+column+" = %s", (value,))
        res = utils.stringify_dt(cur.fetchone())
        cur.close()
        return res
    
    def insert(self, vid, vname, vip, vkey, vstatus):
        cur = self.cursor()
        cur.execute("INSERT INTO status (id,name,ip,key,status,ipy_on,reserved) VALUES (%s,%s,%s,%s,%s,%s,%s);", (vid,vname,vip,vkey,vstatus,False,False))
        cur.close()
        
    def update(self, vid, reserve=None, status=None, access=None, ipy=None, user=None, port=None):
        cur = self.cursor()
        if reserve is not None:
            cur.execute("UPDATE status SET reserved = %s WHERE id = %s", (reserve, vid))
        if status is not None:
            cur.execute("UPDATE status SET status = %s, last_status = %s WHERE id = %s", (status, str(datetime.now()), vid))
        if access is not None:
            cur.execute("UPDATE status SET last_access = %s WHERE id = %s", (access, vid))
        if ipy is not None:
            cur.execute("UPDATE status SET ipy_on = %s WHERE id = %s", (ipy, vid))
        if user and port:
            cur.execute("UPDATE status SET user = %s, port = %s WHERE id = %s", (user, port, vid))
        cur.close()
        return self.get('id', vid)
    
    def delete(self, vid):
        cur = self.cursor()
        cur.execute("DELETE FROM status WHERE id = %s", (vid,))
        cur.close()
    
    def reserve(self):
        cur = self.cursor(True)
        cur.execute("SELECT * FROM status WHERE user IS NULL AND reserve = %s", (False,))
        res = cur.fetchall()
        cur.close()
        if res and (len(res) > 0):
            self.update(res[0]['id'], reserve=True)
            return utils.stringify_dt(res[0])
        else:
            return None
    
    def next_port(self, start, stop):
        cur = self.cursor()
        cur.execute("SELECT port FROM status WHERE port IS NOT NULL")
        ports = map(lambda x: x[0], cur.fetchall())
        cur.close()
        new = random.randrange(start, stop+1)
        while new in ports:
            new = random.randrange(start, stop+1)
        return new
    
    def next_val(self):
        cur = self.cursor()
        cur.execute("SELECT MAX(_id) FROM status")
        next_num = cur.fetchone()[0] + 1
        cur.close()
        return next_num
        
    def exit(self):
        self.handle.commit()
        self.handle.close()
