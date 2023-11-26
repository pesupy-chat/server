import mysql.connector as sqltor
from uuid import uuid4
import pickle
from . import encryption as en
from i18n import log



initialize_ddl = """DROP SCHEMA IF EXISTS pfyt_accounts;
CREATE DATABASE IF NOT EXISTS pfyt_accounts;
CREATE TABLE IF NOT EXISTS pfyt_accounts.users (
    UUID char(36) PRIMARY KEY, 
    USERNAME varchar(32) UNIQUE NOT NULL, 
    FULL_NAME varchar(80) NOT NULL, 
    DOB date NOT NULL, 
    EMAIL varchar(32) DEFAULT NULL, 
    CREATION timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS pfyt_accounts.auth (
    UUID char(36) NOT NULL REFERENCES pfyt_accounts.users(UUID) ON DELETE CASCADE ON UPDATE CASCADE, 
    SALTED_HASHBROWN blob NOT NULL, 
    TOKEN_SECRET tinytext
);
"""

queries = {'initialize': initialize_ddl}
fields_to_check = {
    'username':{'table':'pfyt_accounts.users','attribute':'USERNAME'}}
class db:
    con = None
    cur = None

def decrypt_creds(fkey, workingdir):
    with open(f'{workingdir}/creds/db', 'rb') as f:
        data = f.read()
    decrypted = fkey.decrypt(data)
    dict = pickle.loads(decrypted)
    try:
        setattr(db, 'con', sqltor.connect(host = dict['host'], user = dict['user'], passwd = dict['passwd']))
        setattr(db, 'cur', db.con.cursor())
        if db.con.is_connected():
            print(log.tags.info + log.conn.db_conn_success.format(dict['host'],dict['port']))
            db.cur.execute("USE pfyt_accounts")
    except sqltor.errors.ProgrammingError as errrr:
        print(log.tags.error + log.conn.db_conn_err.format(errrr))

def initialize_schemas():
    try:
        query = queries['initialize'].rstrip(';').split(';\n')
        for i in query:
            db.cur.execute(i)
            db.con.commit()
        print(log.tags.info + log.tags.db.init_success)
    except Exception as error:
        print(log.tags.error + log.tags.db.init_fail.format(error))

def check_if_exists(value, field):
    col = fields_to_check[field]['attribute']
    table = fields_to_check[field]['table']
    db.cur.execute(f"SELECT {col} FROM {table} WHERE {col} = '{value}'")
    data = db.cur.fetchall() 
    try:
        if data[0][0] == value:
            return True
    except IndexError:
        return False
    else:
        return False

def get_uuid(identifier):
    try:
        if '@' not in identifier:
            db.cur.execute("SELECT UUID FROM pfyt_accounts.users WHERE USERNAME=%s", (identifier,))
            uuid = db.cur.fetchall()[0][0]
        elif '@' in identifier:
            db.cur.execute("SELECT UUID FROM pfyt_accounts.users WHERE EMAIL=%s", (identifier,))
            uuid = db.cur.fetchall()[0][0]
    except IndexError:
        return 'ACCOUNT_DNE'
    return uuid

def close():
    if db.con is not None:
        db.con.close()

class Account(db):
    def create(username, fullname, dob, email, salted_pwd):
        # UUID, USERNAME, FULL_NAME, DOB, EMAIL, CREATION
        uuid = str(uuid4())
        query = "INSERT INTO pfyt_accounts.users(UUID, USERNAME, FULL_NAME, DOB, EMAIL) VALUES (%s, %s, %s, %s, %s)"
        print(f"[DEBUG | for {uuid}]",query)
        db.cur.execute(query, (uuid, username, fullname, dob, email))
        db.con.commit()
        pwd_query = "INSERT INTO pfyt_accounts.auth(UUID, SALTED_HASHBROWN) VALUES (%s, %s)"
        db.cur.execute(pwd_query, (uuid, salted_pwd))
        db.con.commit()
    
    def check_pwd(pwd, identifier):
        try:
            if '@' not in identifier:
                db.cur.execute("SELECT UUID FROM pfyt_accounts.users WHERE USERNAME=%s", (identifier,))
                uuid = db.cur.fetchall()[0][0]
            elif '@' in identifier:
                db.cur.execute("SELECT UUID FROM pfyt_accounts.users WHERE EMAIL=%s", (identifier,))
                uuid = db.cur.fetchall()[0][0]
        except IndexError:
            return 'ACCOUNT_DNE'
        db.cur.execute("SELECT SALTED_HASHBROWN FROM pfyt_accounts.auth WHERE UUID = %s", (uuid,))
        saltedpwd = db.cur.fetchall()[0][0]
        flag = en.db_check_pwd(pwd, saltedpwd)
        return (flag, uuid)

    def set_token(uuid, secret):
        db.cur.execute("UPDATE pfyt_accounts.auth SET TOKEN_SECRET = %s WHERE UUID = %s", (secret, uuid))
        db.con.commit()

    def get_token_key(uuid):
        db.cur.execute("SELECT TOKEN_SECRET FROM pfyt_accounts.auth WHERE UUID = %s", (uuid,))
        try:
            resp = db.cur.fetchall()[0][0]
            if resp:
                return resp
            else:
                return 'TOKEN_NOT_FOUND'
        except IndexError:
            return 'TOKEN_NOT_FOUND'

    def logout(uuid):
        try:
            db.cur.execute("UPDATE pfyt_accounts.auth SET TOKEN_SECRET = NULL WHERE UUID = %s", (uuid,))
            db.con.commit()
            return 'SUCCESS'
        except Exception as err:
            print(err)
            return 'FAILURE'
