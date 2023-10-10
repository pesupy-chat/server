from json import loads
import mysql.connector as sqltor
from uuid import uuid4, UUID
import pickle
from . import encryption as en
from os import urandom


initialize_ddl = """CREATE DATABASE IF NOT EXISTS chatapp_accounts;
USE chatapp_accounts;
CREATE TABLE IF NOT EXISTS users(UUID char(32) NOT NULL, USERNAME varchar(32) NOT NULL, FULL_NAME varchar(80) NOT NULL, DOB date NOT NULL, EMAIL varchar(32) DEFAULT NULL, CREATION timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (UUID));
CREATE TABLE IF NOT EXISTS auth(UUID char(32) NOT NULL, SALTED_HASHBROWN blob NOT NULL, TOKEN tinytext NOT NULL, EXPIRY timestamp NOT NULL, KEY authUUID (UUID), CONSTRAINT authUUID FOREIGN KEY (UUID) REFERENCES users (UUID));
CREATE TABLE IF NOT EXISTS pubkeys(UUID char(32) NOT NULL, PUBKEY blob NOT NULL, KEY UUID (UUID), CONSTRAINT UUID FOREIGN KEY (UUID) REFERENCES users (UUID) ON DELETE CASCADE ON UPDATE CASCADE);
CREATE DATABASE IF NOT EXISTS chatapp_chats;
USE chatapp_chats;
CREATE TABLE IF NOT EXISTS rooms (ID int NOT NULL AUTO_INCREMENT, CREATOR_UUID char(32) NOT NULL, ROOM_TYPE int NOT NULL, MEMBERS blob NOT NULL, CHAT_TABLE tinytext NOT NULL, PRIMARY KEY (ID));
CREATE DATABASE IF NOT EXISTS chatapp_internal;
USE chatapp_internal;
CREATE TABLE IF NOT EXISTS settings (PARAM varchar(64) NOT NULL, VALUE varchar(256) NOT NULL);"""

queries = {'initialize': initialize_ddl}
class DBHandler:
    def __init__(self):
        self.con = None
        self.cur = None

    def decrypt_creds(self, fkey, workingdir):
        with open(f'{workingdir}/creds/db', 'rb') as f:
            data = f.read()
        decrypted = fkey.decrypt(data)
        dict = pickle.loads(decrypted)
        try:
            self.con = sqltor.connect(host = dict['host'], user = dict['user'], passwd = dict['passwd'])
            self.cur = self.con.cursor()
            if self.con.is_connected():
                print('[INFO] Connected to database ',dict['host'],':',dict['port'],sep='')
        except sqltor.errors.ProgrammingError as errrr:
            print('[ERROR] Could not connect to database:', errrr)

    def initialize_schemas(self):
        try:
            query = queries['initialize'].rstrip(';').split('\n')
            for i in query:
                self.cur.execute(i)
                self.con.commit()
                print('[INFO]',i) # print('[INFO] Created schemas successfully')
        except Exception as error:
            print('[ERROR] Failed to create schemas:', error)

    def close(self):
        if self.con is not None:
            self.con.close()

    def config_update(self, setting, config):
        self.cur.execute(f"INSERT INTO chatapp_internal.settings VALUES ('{setting}','{config}')")
        self.con.commit()
    def config_read(self, setting):
        self.cur.execute(f"SELECT VALUE FROM chatapp_internal.settings WHERE PARAM = '{setting}'")
        return self.cur.fetchall()[0][0]

    def acc_create(self, username, fullname, dob, email, salted_pwd):
        # UUID, USERNAME, FULL_NAME, DOB, EMAIL, CREATION
        uuid = str(uuid4())
        self.cur.execute(f"INSERT INTO chatapp_accounts.users(UUID, USERNAME, FULL_NAME, DOB, EMAIL) VALUES ('{uuid}', '{username}', '{fullname}', '{dob}', '{email}')")
        self.con.commit()
        pwd_query_args = (uuid, salted_pwd)
        pwd_query = "INSERT INTO chatapp_accounts.auth(UUID, SALTED_HASHBROWN) VALUES ('%s', %s)"
        self.cur.execute(pwd_query, pwd_query_args)
    def acc_set_pubkey(self, user, key):
        self.cur.execute(f"INSERT INTO chatapp_accounts.pubkeys VALUES('{user}',{key})")
    def acc_check_pwd(self, pwd, identifier):
        try:
            if '@' not in identifier:
                self.cur.execute(f"SELECT UUID FROM chatapp_accounts.users WHERE USERNAME={identifier}")
                uuid = self.cur.fetchall()[0][0]
            elif '@' in identifier:
                self.cur.execute(f"SELECT UUID FROM chatapp_accounts.users WHERE EMAIL={identifier}")
                uuid = self.cur.fetchall()[0][0]
        except IndexError:
            return 'ACCOUNT_DNE'

        self.cur.execute(f"SELECT SALTED_HASHBROWN FROM chatapp_accounts.auth WHERE UUID={uuid}")
        saltedpwd = self.cur.fetchall()[0][0]
        flag = en.db_check_pwd(pwd, saltedpwd)
        return flag
