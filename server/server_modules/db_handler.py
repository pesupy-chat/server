from json import loads
import mysql.connector as sqltor
from uuid import uuid4, UUID
import pickle

initialize = """CREATE DATABASE IF NOT EXISTS `chatapp_accounts`;
USE `chatapp_accounts`;
CREATE TABLE IF NOT EXISTS `users`(`UUID` char(32) NOT NULL, `USERNAME` varchar(32) NOT NULL, `FULL_NAME` varchar(80) NOT NULL, `DOB` date NOT NULL, `EMAIL` varchar(32) DEFAULT NULL, `CREATION` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (`UUID`));
CREATE TABLE IF NOT EXISTS `auth`(`UUID` char(32) NOT NULL, `SALTED_HASHBROWN` blob NOT NULL, `TOKEN` tinytext NOT NULL, `EXPIRY` timestamp NOT NULL, KEY `authUUID` (`UUID`), CONSTRAINT `authUUID` FOREIGN KEY (`UUID`) REFERENCES `users` (`UUID`));
CREATE TABLE IF NOT EXISTS `pubkeys`(`UUID` char(32) NOT NULL, `PUBKEY` blob NOT NULL, KEY `UUID` (`UUID`), CONSTRAINT `UUID` FOREIGN KEY (`UUID`) REFERENCES `users` (`UUID`) ON DELETE CASCADE ON UPDATE CASCADE);
CREATE DATABASE IF NOT EXISTS `chatapp_chats`;
USE `chatapp_chats`;
CREATE TABLE IF NOT EXISTS `rooms` (`ID` int NOT NULL AUTO_INCREMENT, `CREATOR_UUID` char(32) NOT NULL, `ROOM_TYPE` int NOT NULL, `MEMBERS` blob NOT NULL, `TABLE` tinytext NOT NULL, PRIMARY KEY (`ID`));
CREATE DATABASE IF NOT EXISTS `chatapp_internal`;
USE `chatapp_internal`;
CREATE TABLE IF NOT EXISTS `settings` (`PARAM` varchar(64) NOT NULL, `VALUE` varchar(256) NOT NULL);"""

queries = {'initialize': initialize}
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
    query = queries['initialize']
    db.cur.execute(query, multi=True)
    db.con.commit()

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
