#!/usr/bin/env python

import sys
import psycopg2, psycopg2.extras
from datetime import datetime

def clean_dt(data):
    if data:
        if ('vm_start' in data) and data['vm_start']:
            data['vm_start'] = str(data['vm_start'])
        if ('vm_last_access' in data) and data['vm_last_access']:
            data['vm_last_access'] = str(data['vm_last_access'])
    return data

class IpyDB(object):
    def __init__(self, cfg):
        self.handle = None
        self.error = None
        try:
            self.handle = psycopg2.connect(
                host='localhost',
                database=cfg.get("psql", "name"),
                user=cfg.get("psql", "user"),
                password=cfg.get("psql", "password") )
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
                vm_id uuid UNIQUE NOT NULL,
                vm_name text NOT NULL,
                vm_ip inet NOT NULL,
                vm_start TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                vm_last_access TIMESTAMP,
                ipy_on BOOLEAN NOT NULL,
                user_name TEXT,
                user_port INTEGER
            );""")
        cur.execute("CREATE INDEX status_vm ON status (vm_id);")
        cur.execute("CREATE INDEX status_user ON status (user_name);")
        cur.close()
    
    def list(self):
        cur = self.cursor(True)
        cur.execute("SELECT * FROM status")
        res = map(lambda x: clean_dt(x), cur.fetchall())
        cur.close()
        return res
        
    def get(self, column, value):
        cur = self.cursor(True)
        cur.execute("SELECT * FROM status WHERE "+column+" = %s", (value,))
        res = clean_dt(cur.fetchone())
        cur.close()
        return res
    
    def insert(self, vid, vname, vip):
        cur = self.cursor()
        cur.execute("INSERT INTO status (vm_id,vm_name,vm_ip,ipy_on) VALUES (%s,%s,%s,%s);", (vid,vname,vip,False))
        cur.close()
        
    def update(self, vid, access=None, ipy=None, user=None, port=None):
        cur = self.cursor()
        if access is not None:
            cur.execute("UPDATE status SET vm_last_access = %s WHERE vm_id = %s", (access, vid))
        if ipy is not None:
            cur.execute("UPDATE status SET ipy_on = %s WHERE vm_id = %s", (ipy, vid))
        if user and port:
            cur.execute("UPDATE status SET user_name = %s, user_port = %s WHERE vm_id = %s", (ipy, vid))
        cur.close()
    
    def delete(self, vid):
        cur = self.cursor()
        cur.execute("DELETE FROM status WHERE vm_id = %s", (vid,))
        cur.close()
    
    def next_val():
        cur = self.cursor()
        cur.execute("SELECT MAX(_id) FROM status")
        next = cur.fetchone()[0] + 1
        cur.close()
        return next
        
    def exit():
        self.handle.commit()
        self.handle.close()