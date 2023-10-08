from . import encryption as en
from os import urandom
import mysql.connector as sqltor
from uuid import uuid4
import pickle

initialize_ddl = """CREATE SCHEMA IF NOT EXISTS `chatapp_accounts`;
USE `chatapp_accounts`;
CREATE TABLE IF NOT EXISTS `users`(`UUID` char(32) NOT NULL, `USERNAME` varchar(32) NOT NULL, `FULL_NAME` varchar(80) NOT NULL, `DOB` date NOT NULL, `EMAIL` varchar(32) DEFAULT NULL, `CREATION` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (`UUID`));
CREATE TABLE IF NOT EXISTS `auth`(`UUID` char(32) NOT NULL, `SALTED_HASHBROWN` blob NOT NULL, `TOKEN` tinytext NOT NULL, `EXPIRY` timestamp NOT NULL, KEY `authUUID` (`UUID`), CONSTRAINT `authUUID` FOREIGN KEY (`UUID`) REFERENCES `users` (`UUID`));
CREATE TABLE IF NOT EXISTS `pubkeys`(`UUID` char(32) NOT NULL, `PUBKEY` blob NOT NULL, KEY `UUID` (`UUID`), CONSTRAINT `UUID` FOREIGN KEY (`UUID`) REFERENCES `users` (`UUID`) ON DELETE CASCADE ON UPDATE CASCADE);
CREATE SCHEMA IF NOT EXISTS `chatapp_chats`;
USE `chatapp_chats`;
CREATE TABLE IF NOT EXISTS `rooms` (`ID` int NOT NULL AUTO_INCREMENT, `CREATOR_UUID` char(32) NOT NULL, `ROOM_TYPE` int NOT NULL, `MEMBERS` blob NOT NULL, `TABLE` tinytext NOT NULL, PRIMARY KEY (`ID`));
CREATE SCHEMA IF NOT EXISTS `chatapp_internal`;
USE `chatapp_internal`;
CREATE TABLE IF NOT EXISTS `settings` (`PARAM` varchar(64) NOT NULL, `VALUE` varchar(256) NOT NULL);"""

initialize_dml = """
"""

queries = {'initialize': initialize_ddl}
class db:
    con = ()
    cur = ()

def decrypt_creds(fkey, workingdir):
    with open(f'{workingdir}/creds/db', 'rb') as f:
        data = f.read()
    decrypted = fkey.decrypt(data)
    dict = pickle.loads(decrypted)
    try:
        setattr(db, 'con', sqltor.connect(host = dict['host'], user = dict['user'], passwd = dict['passwd']))
        setattr(db, 'cur', db.con.cursor())
        print('[INFO] Connected to database ',dict['host'],':',dict['port'],sep='')
    except sqltor.errors.ProgrammingError as errrr:
        print('[ERROR] Could not connect to database:', errrr)

class Config(db):
    @staticmethod
    def update(setting, config):
        db.cur.execute(f"INSERT INTO chatapp_internal.settings VALUES ('{setting}','{config}')")
        db.con.commit()
    def read(setting):
        db.cur.execute(f"SELECT VALUE FROM chatapp_internal.settings WHERE PARAM = '{setting}'")
        return db.cur.fetchall()[0][1]

class Account(db):
    @staticmethod
    def create(username, fullname, dob, email, salted_pwd):
        # UUID, USERNAME, FULL_NAME, DOB, EMAIL, CREATION
        uuid = str(uuid4())
        db.cur.execute(f"INSERT INTO chatapp_accounts.`users`(UUID, USERNAME, FULL_NAME, DOB, EMAIL) VALUES ('{uuid}', '{username}', '{fullname}', '{dob}', {email})")
        db.con.commit()
        db.cur.execute(f"INSERT INTO chatapp_accounts.`auth`(UUID, SALTED_HASHBROWN) VALUES ('{uuid}', '{salted_pwd}')")
    def set_pubkey(user, key):
        db.cur.execute(f"INSERT INTO chatapp_accounts.`pubkeys` VALUES('{user}',key)")
    def check_pwd(pwd, identifier):
        try:
            if '@' not in identifier:
                db.cur.execute(f"SELECT UUID FROM chatapp_accounts.`users` WHERE USERNAME={identifier}")
                uuid = db.cur.fetchall()[0][0]
            elif '@' in identifier:
                db.cur.execute(f"SELECT UUID FROM chatapp_accounts.`users` WHERE EMAIL={identifier}")
                uuid = db.cur.fetchall()[0][0]
        except IndexError:
            return 'ACCOUNT_DNE'

        db.cur.execute(f"SELECT SALTED_HASHBROWN FROM chatapp_accounts.`auth` WHERE UUID={uuid}")
        saltedpwd = db.cur.fetchall()[0][0]
        flag = en.db_check_pwd(pwd, saltedpwd)
        return flag

def initialize_schemas():
    query = queries['initialize']
    try:
        db.cur.execute(query, multi=True)
        db.con.commit()
        print('[INFO] Created schemas successfully')
    except Exception as error:
        print('[ERROR] Failed to create schemas:', error)

def save_salt():
    try:
        db.cur.execute("USE chatapp_internal")
        query = f"INSERT INTO settings VALUES ('PASS_SALT', %s)"
        db.cur.execute(query, (urandom(16),))
        db.con.commit()
    except Exception as eror:
        print('[ERROR] Failed to save password salt:', eror)