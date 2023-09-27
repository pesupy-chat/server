from json import loads
import mysql.connector as sqltor
from uuid import uuid4
import pickle
class db:
    con = ()
    cur = ()

def decrypt_creds(fkey, workingdir):
    with open(f'{workingdir}/creds/db', 'rb') as f:
        data = f.read()
    decrypted = fkey.decrypt(data)
    dict = pickle.loads(decrypted)
    setattr(db, 'con', sqltor.connect(host = dict['host'], user = dict['user'], passwd = dict['passwd']))
    setattr(db, 'cur', db.con.cursor())

def initialize_schemas():
    f = open('database.sql', 'r')
    query = f.read()
    db.cur.execute(query, multi=True)
    db.con.commit()
    f.close()

class Config(db):
    @staticmethod
    def update(setting, config):
        db.cur.execute(f"INSERT INTO chatapp_internal.settings VALUES ('{setting}','{config}')")
        db.con.commit()
    def read(setting):
        db.cur.execute(f"SELECT VALUE FROM chatapp_internal.settings WHERE PARAM = '{setting}'")
        return db.cur.fetchall()[0][1]

"""
class Accounts(db):
    @staticmethod
    def create(username, name, pwd):
        uuid = str(uuid4())
        db.cur.execute(f"INSERT INTO chatapp_users.ACCOUNTS VALUES('{uuid}','{username}', '{name}', {pwd})")
        db.con.commit()
    def set_pubkey(user, key):
        db.cur.execute(f"INSERT INTO chatapp_users.PUBKEYS VALUES('{user}',)")
"""
