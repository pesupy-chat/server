import mysql.connector as sqltor
from uuid import uuid4
import pickle
from . import encryption as en



initialize_ddl = """CREATE DATABASE IF NOT EXISTS chatapp_accounts;
USE chatapp_accounts;
CREATE TABLE IF NOT EXISTS users (
    UUID char(36) NOT NULL, 
    USERNAME varchar(32) UNIQUE NOT NULL, 
    FULL_NAME varchar(80) NOT NULL, 
    DOB date NOT NULL, 
    EMAIL varchar(32) DEFAULT NULL, 
    CREATION timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP, 
    PRIMARY KEY (UUID)
);
CREATE TABLE IF NOT EXISTS auth (
    UUID char(36) NOT NULL, 
    SALTED_HASHBROWN blob NOT NULL, 
    TOKEN_SECRET tinytext, 
    KEY authUUID (UUID), 
    CONSTRAINT authUUID FOREIGN KEY (UUID) REFERENCES users (UUID)
);
CREATE TABLE IF NOT EXISTS pubkeys (
    UUID char(36) NOT NULL, 
    PUBKEY blob NOT NULL, 
    KEY UUID (UUID), 
    CONSTRAINT UUID FOREIGN KEY (UUID) REFERENCES users (UUID) ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE DATABASE IF NOT EXISTS chatapp_chats;
USE chatapp_chats;
CREATE TABLE IF NOT EXISTS rooms (
    ID int NOT NULL AUTO_INCREMENT, 
    CREATOR_UUID char(36) NOT NULL, 
    ROOM_TYPE int NOT NULL, 
    MEMBERS blob NOT NULL, 
    CHAT_TABLE tinytext NOT NULL, 
    PRIMARY KEY (ID), 
    KEY creatorUUID (CREATOR_UUID), 
    CONSTRAINT creatorUUID FOREIGN KEY REFERENCES chatapp_accounts.users (UUID)
);
CREATE DATABASE IF NOT EXISTS chatapp_internal;
USE chatapp_internal;
CREATE TABLE IF NOT EXISTS settings (PARAM varchar(64) NOT NULL, VALUE varchar(256) NOT NULL);
CREATE TABLE IF NOT EXISTS `message_queue` (
    `timestamp` timestamp PRIMARY KEY DEFAULT CURRENT_TIMESTAMP, 
    `recipientUUID` char(36) NOT NULL, 
    `packet` mediumblob NOT NULL
);"""

createroom = """CREATE TABLE chatapp_chats.{0} (
  `messageID` int NOT NULL AUTO_INCREMENT,
  `messageUUID` char(36) UNIQUE NOT NULL,
  `sender` char(36) NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `message` mediumblob NOT NULL,
  `type` varchar(16) NOT NULL,
  `pinned` bool NOT NULL DEFAULT false,
  PRIMARY KEY (`messageID`)
);"""

queries = {'initialize': initialize_ddl, 'create_room':createroom}
fields_to_check = {
    'username':{'table':'chatapp_accounts.users','attribute':'USERNAME'},
    'room':{'table':'chatapp_chats.rooms', 'attribute':'CHAT_TABLE'}
    }
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
            print('[INFO] Connected to database ',dict['host'],':',dict['port'],sep='')
    except sqltor.errors.ProgrammingError as errrr:
        print('[ERROR] Could not connect to database:', errrr)

def initialize_schemas():
    try:
        query = queries['initialize'].rstrip(';').split('\n')
        for i in query:
            db.cur.execute(i)
            db.con.commit()
            print('[DEBUG]',i) # print('[INFO] Created schemas successfully')
    except Exception as error:
        print('[ERROR] Failed to create schemas:', error)

def check_if_exists(value, field):
    col = fields_to_check[field]['attribute']
    table = fields_to_check[field]['table']
    db.cur.execute(f"select {col} from {table} where {col} = '{value}'")
    data = db.cur.fetchall() 
    try:
        if data[0][0] == value:
            return True
    except IndexError:
        return False

def check_pubkey(uuid):
    db.cur.execute(f"SELECT PUBKEY FROM chatapp_accounts.pubkeys WHERE UUID = '{uuid}'")
    data = db.cur.fetchall()
    if len(data) == 0:
        return False
    elif len(data) == 1:
        return True

def get_uuid(identifier):
    try:
        if '@' not in identifier:
            db.cur.execute("SELECT UUID FROM chatapp_accounts.users WHERE USERNAME=%s", (identifier,))
            uuid = db.cur.fetchall()[0][0]
        elif '@' in identifier:
            db.cur.execute("SELECT UUID FROM chatapp_accounts.users WHERE EMAIL=%s", (identifier,))
            uuid = db.cur.fetchall()[0][0]
    except IndexError:
        return 'ACCOUNT_DNE'
    return uuid

def queue_packet(user_uuid, de_packet, SERVER_CREDS):
    en_packet = en.encrypt_packet(de_packet, SERVER_CREDS['queue_pubkey'])
    db.cur.execute("INSERT INTO chatapp_internal.message_queue(recipientUUID, packet) VALUES (%s, %s)", (user_uuid, en_packet))
    db.con.commit()

def clear_queue(user: str | None):
    if user:
        db.cur.execute("DELETE FROM chatapp_internal.message_queue WHERE recipientUUID = %s", (user,))
        db.con.commit()
    elif not user:
        db.cur.execute("DELETE FROM chatapp_internal.message_queue WHERE packet IS NOT NULL")
        db.con.commit()

def flush_queue(user_uuid):
    db.cur.execute("SELECT packet FROM chatapp_internal.message_queue WHERE recipientUUID = %s", (user_uuid,))
    return db.cur.fetchall()

def close():
    if db.con is not None:
        db.con.close()
class Config(db):
    def update(setting, config):
        db.cur.execute("INSERT INTO chatapp_internal.settings VALUES (%s, %s)", (setting, config))
        db.con.commit()
    
    def read(setting):
        db.cur.execute("SELECT VALUE FROM chatapp_internal.settings WHERE PARAM = %s", (setting,))
        return db.cur.fetchall()[0][0]

class Account(db):
    def create(username, fullname, dob, email, salted_pwd):
        # UUID, USERNAME, FULL_NAME, DOB, EMAIL, CREATION
        uuid = str(uuid4())
        query = "INSERT INTO chatapp_accounts.users(UUID, USERNAME, FULL_NAME, DOB, EMAIL) VALUES (%s, %s, %s, %s, %s)"
        print(f"[DEBUG | for {uuid}]",query)
        db.cur.execute(query, (uuid, username, fullname, dob, email))
        db.con.commit()
        pwd_query = "INSERT INTO chatapp_accounts.auth(UUID, SALTED_HASHBROWN) VALUES (%s, %s)"
        print(f"[DEBUG | for {uuid}]", pwd_query)
        db.cur.execute(pwd_query, (uuid, salted_pwd))
        db.con.commit()
    
    def set_pubkey(user, key):
        db.cur.execute("INSERT INTO chatapp_accounts.pubkeys VALUES(%s, %s)", (user, key))
        db.con.commit()
    
    def check_pwd(pwd, identifier):
        try:
            if '@' not in identifier:
                db.cur.execute("SELECT UUID FROM chatapp_accounts.users WHERE USERNAME=%s", (identifier,))
                uuid = db.cur.fetchall()[0][0]
            elif '@' in identifier:
                db.cur.execute("SELECT UUID FROM chatapp_accounts.users WHERE EMAIL=%s", (identifier,))
                uuid = db.cur.fetchall()[0][0]
        except IndexError:
            return 'ACCOUNT_DNE'
        db.cur.execute("SELECT SALTED_HASHBROWN FROM chatapp_accounts.auth WHERE UUID = %s", (uuid,))
        saltedpwd = db.cur.fetchall()[0][0]
        flag = en.db_check_pwd(pwd, saltedpwd)
        return (flag, uuid)

    def set_token(uuid, secret):
        db.cur.execute("UPDATE chatapp_accounts.auth SET TOKEN_SECRET = %s WHERE UUID = %s", (secret, uuid))
        db.con.commit()
    def get_token_key(uuid):
        db.cur.execute("SELECT TOKEN_SECRET FROM chatapp_accounts.auth WHERE UUID = %s", (uuid,))
        return db.cur.fetchall()[0][0]
    
class Room(db):
    def create(creator, data):
        if data['room_type'] == 0 and len(data['members']) == 0 or len(data['members']) > 1:
            return 'MKROOM_ERROR'
        elif len(data['members']) > 1:
            return 'NOT_IMPLEMENTED'
        # room_type 1 is for group, 2 for broadcast
        chat_table = str(uuid4()).replace('-', '')
        members_db, members_dne = [creator], []
        for user in data['members']:
            flag = check_if_exists(user, 'username')
            if flag == True:
                members_db.append(get_uuid(user))
            elif flag == False:
                members_dne.append(user)
        members_insert = pickle.dumps(members_db)
        try:
            db.cur.execute(queries['create_room'].format(chat_table))
            query = "INSERT INTO chatapp_chats.rooms(CREATOR_UUID, ROOM_TYPE, ROOM_NAME, MEMBERS, CHAT_TABLE) VALUES (%s, %s, %s, %s, %s)"
            db.cur.execute(query, (data['members'][0], data['room-type'], data['room-name'], members_insert, chat_table))
            db.con.commit()
            match data['room-type']:
                case 0:
                    return ['MKROOM_OK', data['room-type'], data['room-name'], chat_table, members_db, members_dne]
            
        except:
            return 'MKROOM_ERROR'
    
    def fetch_info(room_uuid):
        """[intid, creator_uuid, room_type, members, chat_table]"""
        db.cur.execute("SELECT * FROM chatapp_chats.rooms WHERE CHAT_TABLE = %s", (room_uuid,))
        data = db.con.fetchall()
        if data == []:
            return 'ROOM_DNE'
        return data[0]

class Chat(db):
    def save_msg(sender, data):
        """
        data = room, action, actiondata(send/edit/delete/pin formats)"""
        room_uuid, action, actiondata = data['room'], data['action'], data['actiondata']
        match action:
            case 'send':
                db.cur.execute(f"INSERT INTO chatapp_chats.{room_uuid}(messageUUID, sender, message, type) VALUES (%s, %s, %s, %s)", (str(uuid4()), sender, actiondata['content'], actiondata['format']))
                db.con.commit()
                return 'SUCCESS'
            case 'edit':
                msg = data['actiondata']['msg']
                db.cur.execute(f"SELECT sender FROM chatapp_chats.{room_uuid} WHERE messageUUID = %s", (msg,))
                o_sender = db.cur.fetchall()[0][0]
                if sender == o_sender:
                    db.cur.execute(f"UPDATE chatapp_chats.{room_uuid} SET message = %s, type = %s WHERE messageUUID = %s", (actiondata['content'], actiondata['format'], actiondata['msg']))
                    db.con.commit()
                    return 'SUCCESS'
                else:
                    return 'NOT_YOURS'
            case 'delete':
                msg = data['actiondata']['msg']
                db.cur.execute(f"SELECT sender FROM chatapp_chats.{room_uuid} WHERE messageUUID = %s", (msg,))
                o_sender = db.cur.fetchall()[0][0]
                if sender == o_sender:
                    db.cur.execute(f"UPDATE chatapp_chats.{room_uuid} SET message = 'DELETED', type = 'sig' WHERE messageUUID = %s", (msg,))
                    db.con.commit()
                    return 'SUCCESS'
                else:
                    return 'NOT_YOURS'
            case 'pinned':
                db.cur.execute(f"UPDATE chatapp_chats.{room_uuid} SET pinned = true WHERE messageUUID = %s", (msg,))
                db.con.commit()
                return 'SUCCESS'
