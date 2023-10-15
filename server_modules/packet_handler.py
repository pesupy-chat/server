from uuid import UUID
import asyncio
import pickle
from . import encryption as en
from . import db_handler as db
from uuid import UUID
from cryptography.hazmat.primitives import serialization as s
from captcha.image import ImageCaptcha
from random import randint
import datetime

async def identify_client(websocket, SESSIONS):
    return list(SESSIONS.keys())[[i[0] for i in list(SESSIONS.values())].index(websocket)]

async def disconnect(ws, code, reason):
    print(f"[INFO] CLIENT {ws.remote_address} DISCONNECTED due to",code,reason)
    await ws.close(code=code, reason=reason)
    return 'CONN_CLOSED'

#async def get_packet(ws, type):
#    # packet validator

async def establish_conn(SESSIONS, SERVER_CREDS, ws, data):
    print(f"[INFO] Remote {ws.remote_address} attempted connection")
    try:
        uuid = UUID(data, version=4)
    except ValueError:
        await ws.close(code = 1008, reason = "Connection UUID Invalid")
        return 'CONN_CLOSED'
    if uuid in SESSIONS.keys():
        await ws.close(code = 1008, reason = "Connection UUID Already in use")
        return 'CONN_CLOSED'
    SESSIONS[uuid] = [ws, None, None] # ws, public_key, user_uuid

    print(f"[INFO] {uuid} CONN_INIT: {ws.remote_address}")
    print(f"[INFO] SENDING PUBLIC KEY to {uuid}")

    # Encrypt Connection
    await ws.send(pickle.dumps({'type':'CONN_ENCRYPT_S','data':SERVER_CREDS['server_epbkey']}))
    try:
        client_epbkey = pickle.loads(await ws.recv())
        try:
            client_epbkey = s.load_pem_public_key(client_epbkey['data'])
        except Exception as e:
            print(f"[INFO] CLIENT un-established {ws.remote_address} DISCONNECTED due to INVALID_PACKET")
            await ws.close(code = 1008, reason = "Invalid packet structure")
            return 'CONN_CLOSED'
        
        SESSIONS[uuid][1] = client_epbkey
        print(f"[INFO] Received public key for {ws.remote_address}")
        del client_epbkey
        return en.encrypt_packet(
            {'type':'STATUS', 'data':{'sig':'CONN_OK'}},
            SESSIONS[uuid][1],
            )
    # If client sends bullshit instead of its PEM serialized ephemeral public key
    except Exception as err2:
        print(f"[INFO] CLIENT {uuid} {ws.remote_address} DISCONNECTED due to INVALID_CONN_KEY:\n\t",err2)
        await ws.close(code = 1003, reason = "Connection Public Key in invalid format")
        del SESSIONS[uuid]
        return 'CONN_CLOSED'
    
async def get_resp_packet(SESSIONS, ws, de_packet):
    uuid = await identify_client(ws, SESSIONS)
    en_packet = en.encrypt_packet(de_packet, SESSIONS[uuid][1])
    return en_packet

async def signup(SESSIONS, SERVER_CREDS, ws, data):
    uuid = list(SESSIONS.keys())[[i[0] for i in list(SESSIONS.values())].index(ws)]
    try:
        user = data['user']
        email = data['email']
        fullname = data['fullname']
        dob = datetime.strpdata['dob']
        password = data['password']
    except KeyError as ero:
        return await get_resp_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'SIGNUP_MISSING_CREDS','desc':ero}})
    if len(user) > 32:
        return await get_resp_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'SIGNUP_USERNAME_ABOVE_LIMIT'}})
    elif db.check_if_exists(user, 'username'):
        return await get_resp_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'SIGNUP_USERNAME_ALREADY_EXISTS'}})
    elif len(email) > 256:
        return await get_resp_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'SIGNUP_EMAIL_ABOVE_LIMIT'}})
    elif len(fullname) > 256:
        return await get_resp_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'SIGNUP_NAME_ABOVE_LIMIT'}})
    elif len(dob) > 10:
        return await get_resp_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'SIGNUP_DOB_INVALID'}})
    elif len(password) > 384:
        return await get_resp_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'SIGNUP_PASSWORD_ABOVE_LIMIT'}})
    resp_captcha = await captcha(SESSIONS, SERVER_CREDS, ws, data)
    if resp_captcha == True:
        print(f"[INFO] CLIENT {uuid} ATTEMPTED SIGNUP WITH username {user}")
        salted_pwd = en.salt_pwd(password)
        try:
            db.Account.create(user, fullname, dob, email, salted_pwd)
        except Exception as errr:
            return await get_resp_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'SIGNUP_ERR','desc':errr}})
        else:
            return await get_resp_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'SIGNUP_OK'}})
    elif resp_captcha == False:
        return await get_resp_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'CAPTCHA_WRONG'}})

async def login(SESSIONS, SERVER_CREDS, ws, data):
    try:
        identifier = data['id']
        password = data['password']
        dont_ask_again = data['save']
    except KeyError as ero:
        return await get_resp_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'LOGIN_MISSING_CREDS','desc':ero}})
    resp_captcha = await captcha(SESSIONS, SERVER_CREDS, ws, data)
    if resp_captcha == True:
        flag, uuid = db.Account.check_pwd(password, identifier)
        if flag == True:
            if dont_ask_again == True:
                secret, access_token = en.gen_token(uuid, 30)
            else:
                secret, access_token = en.gen_token(uuid, 1)
            db.Account.set_token(uuid, secret)
            en_packet = await get_resp_packet(SESSIONS, ws, {'type':'TOKEN_GEN','data':{'token':access_token}})
            pubkey_resp = await get_pubkey(SESSIONS, SERVER_CREDS, ws, uuid)
            if pubkey_resp == 'CONN_CLOSED':
                return 'CONN_CLOSED'
            elif pubkey_resp == 'CHAT_PUBKEY_OK':
                return en_packet
        elif flag == False:
            return await get_resp_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'LOGIN_INCORRECT_PASSWORD'}})
        elif flag == 'ACCOUNT_DNE':
            return await get_resp_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'LOGIN_ACCOUNT_NOT_FOUND'}})
    elif resp_captcha == False:
        return await get_resp_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'CAPTCHA_WRONG'}})

async def auth(SESSIONS, SERVER_CREDS, ws, data):
    user = data['data']['user']
    token = data['data']['token']
    con_uuid = await identify_client(ws, SESSIONS)
    user_uuid = db.get_uuid(user)
    key = db.Account.get_token_key(user_uuid)
    flag = en.validate_token(key, token, con_uuid)
    if flag == 'TOKEN_OK':
        SESSIONS[con_uuid][2] = user_uuid
        return await get_resp_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'LOGIN_OK'}})
    elif flag == 'TOKEN_EXPIRED':
        return await get_resp_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'TOKEN_EXPIRED'}})
    elif flag == 'TOKEN_INVALID':
        return await get_resp_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'TOKEN_INVALID'}})

async def get_pubkey(SESSIONS, SERVER_CREDS, ws, uuid):
    flag = db.check_pubkey(uuid)
    if flag == False:
        await ws.send(await get_resp_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'CHAT_PUBKEY_MISSING'}}))
        while True:
            de_pubkey = pickle.loads(en.decrypt_packet(await ws.recv(), SERVER_CREDS['server_eprkey']))
            if de_pubkey['type'] == 'CHAT_ENCRYPT_C':
                try:
                    s.load_pem_public_key(de_pubkey['data']['chat_pubkey'])
                except Exception as ear:
                    await ws.send(await get_resp_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'CHAT_PUBKEY_INVALID'}}))
                else:
                    db.Account.set_pubkey(uuid, de_pubkey['data']['chat_pubkey'])
                    await ws.send(await get_resp_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'CHAT_PUBKEY_OK'}}))
                    return 'CHAT_PUBKEY_OK'
            else:
                print(f"[INFO] CLIENT un-established {ws.remote_address} DISCONNECTED due to INVALID_PACKET")
                await ws.close(code = 1008, reason = "Invalid packet structure")
                return 'CONN_CLOSED'
    elif flag == True:
        return 'CHAT_PUBKEY_OK'

async def captcha(SESSIONS, SERVER_CREDS, ws, data):
    uuid = await identify_client(ws, SESSIONS)
    challenge = str(randint(100000,999999))
    data = ImageCaptcha().generate(challenge)
    image = data.getvalue()

    packet = en.encrypt_packet({'type':'CAPTCHA', 'data':{'challenge':image}}, SESSIONS[uuid][1])
    await ws.send(packet)
    print(f"[INFO] GENERATED CAPTCHA FOR CLIENT {uuid} with CODE {challenge}")
    resp = await ws.recv()

    # handle possible INVALID_PACKET in next line 
    de_resp = pickle.loads(en.decrypt_packet(resp, SERVER_CREDS['server_eprkey']))
    de_resp = de_resp['data']['solved']
    return int(de_resp) == int(challenge)

upacket_map = {
    'CONN_INIT':1,
    'CONN_ENCRYPT_C':2
}
packet_map = {
    'SIGNUP':signup,
    'LOGIN':login,
    'CHAT_ENCRYPT_C':4,
    'AUTHENTICATE':6,
    'CREATE_ROOM':5,
    'CHAT_ACTION':7,
    'ALTER_ROOM':8,
    'LOGOUT':9
}

async def handle(SESSIONS, SERVER_CREDS, packet, ws):
    if 'type'.encode() in packet:
        de_packet = pickle.loads(packet)
    else:
        de_packet = en.decrypt_packet(packet, SERVER_CREDS['server_eprkey'])

    if de_packet['type'] == 'INVALID_PACKET':
        await disconnect(ws, 1008, "Invalid Packet Structure")
        return 'CONN_CLOSED'
    else:
        type = de_packet['type']
        data = de_packet['data']

    if type == 'CONN_INIT':
        return await establish_conn(SESSIONS, SERVER_CREDS, ws, data)
    elif type in packet_map.keys():
        func = packet_map[type]
        return await func(SESSIONS, SERVER_CREDS, ws, data)
    else:
        await disconnect(ws, 1008, "Invalid Packet Structure")
        return 'CONN_CLOSED'

