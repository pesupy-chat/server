import mysql.connector as sqltor
from uuid import uuid4

class db:
    con = []
    cur = []

def initialize():
    db.cur.execute("CREATE SCHEMA IF NOT EXISTS chatapp_internal")
    db.cur.execute("CREATE SCHEMA IF NOT EXISTS chatapp_chats")
    db.cur.execute("CREATE SCHEMA IF NOT EXISTS chatapp_users")
    db.con.commit()
    db.cur.execute("CREATE TABLE IF NOT EXISTS chatapp_internal.CONFIG(SETTING VARCHAR(25) NOT NULL UNIQUE, CONFIG VARCHAR(512))")
    db.cur.execute("CREATE TABLE IF NOT EXISTS chatapp_users.ACCOUNTS(UUID VARCHAR(36) PRIMARY KEY, USERNAME VARCHAR(24) UNIQUE NOT NULL, NAME VARCHAR(128) NOT NULL, PASSWORD VARBINARY NOT NULL)")
    db.cur.execute("CREATE TABLE IF NOT EXISTS chatapp_users.PUBKEYS(UUID VARCHAR(36) PRIMARY KEY REFERENCES chatapp_users.ACCOUNTS, PUBKEY VARBINARY NOT NULL)")
    db.cur.execute("CREATE TABLE IF NOT EXISTS chatapp_chats.ROOMS()")
    db.con.commit()

class Config(db):
    @staticmethod
    def update(setting, config):
        db.cur.execute(f"INSERT INTO chatapp_internal.CONFIG VALUES ('{setting}','{config}')")
        db.con.commit()
    def read(setting):
        db.cur.execute(f"SELECT CONFIG FROM chatapp_internal.CONFIG WHERE SETTING = '{setting}'")
        return db.cur.fetchall()[0][1]


class Accounts(db):
    @staticmethod
    def create(username, name, pwd):
        uuid = str(uuid4())
        db.cur.execute(f"INSERT INTO chatapp_users.ACCOUNTS VALUES('{uuid}','{username}', '{name}', {pwd})")
        db.con.commit()
    def set_pubkey(user, key):
        db.cur.execute(f"INSERT INTO ACCOUNTS VALUES('{uuid}','{username}', '{name}', NULL, {pwd})")

