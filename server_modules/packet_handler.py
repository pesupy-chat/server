from uuid import UUID
import asyncio
import pickle
from . import encryption as en
from . import db_handler as db
from uuid import UUID
from cryptography.hazmat.primitives import serialization as s
from captcha.image import ImageCaptcha
from random import randint

async def identify_client(websocket, SESSIONS):
    return list(SESSIONS.keys())[[i[0] for i in list(SESSIONS.values())].index(websocket)]

async def disconnect(ws, code, reason):
    print(f"[INFO] CLIENT {ws.remote_address} DISCONNECTED due to",code,reason)
    await ws.close(code=code, reason=reason)
    return 'CONN_CLOSED'

#async def get_packet(ws, type):
#    # packet validator

async def establish_conn(SESSIONS, SERVER_CREDS, websocket, data):
    print(f"[INFO] Remote {websocket.remote_address} attempted connection")
    try:
        uuid = UUID(data, version=4)
    except ValueError:
        await websocket.close(code = 1008, reason = "Connection UUID Invalid")
        return 'CONN_CLOSED'
    if uuid in SESSIONS.keys():
        await websocket.close(code = 1008, reason = "Connection UUID Already in use")
        return 'CONN_CLOSED'
    SESSIONS[uuid] = [websocket, None, None] # ws, public_key, user_uuid

    print(f"[INFO] {uuid} CONN_INIT: {websocket.remote_address}")
    print(f"[INFO] SENDING PUBLIC KEY to {uuid}")

    # Encrypt Connection
    await websocket.send(pickle.dumps({'type':'CONN_ENCRYPT_S','data':SERVER_CREDS['server_epbkey']}))
    #try:
    client_epbkey = pickle.loads(await websocket.recv())
    try:
        client_epbkey = s.load_pem_public_key(client_epbkey['data'])
    except Exception as e:
        print(f"[INFO] CLIENT un-established {websocket.remote_address} DISCONNECTED due to INVALID_PACKET")
        await websocket.close(code = 1008, reason = "Invalid packet structure")
        return 'CONN_CLOSED'
    
    SESSIONS[uuid][1] = client_epbkey
    print(f"[INFO] Received public key for {websocket.remote_address}")
    del client_epbkey
    return en.encrypt_packet(
        {'type':'STATUS', 'data':{'sig':'CONN_OK'}},
        SESSIONS[uuid][1],
        )
    # If client sends bullshit instead of its PEM serialized ephemeral public key
    """except Exception as err2:
        print(f"[INFO] CLIENT {uuid} {websocket.remote_address} DISCONNECTED due to INVALID_CONN_KEY:\n\t",err2)
        await websocket.close(code = 1003, reason = "Connection Public Key in invalid format")
        del SESSIONS[uuid]
        return 'CONN_CLOSED'"""
    
async def send_packet(SESSIONS, ws, de_packet):
    uuid = await identify_client(ws, SESSIONS)
    en_packet = en.encrypt_packet(de_packet, SESSIONS[uuid][1])
    return en_packet

async def signup(SESSIONS, SERVER_CREDS, ws, data):
    uuid = list(SESSIONS.keys())[[i[0] for i in list(SESSIONS.values())].index(ws)]
    user = data['user']
    email = data['email']
    fullname = data['fullname']
    if len(user) > 32:
        return await send_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'SIGNUP_USERNAME_ABOVE_LIMIT'}})
    if len(email) > 256:
        return await send_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'SIGNUP_EMAIL_ABOVE_LIMIT'}})
    if len(fullname) > 256:
        return await send_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'SIGNUP_NAME_ABOVE_LIMIT'}})
    resp_captcha = await captcha(SESSIONS, SERVER_CREDS, ws, data)
    if resp_captcha == True:
        print(f"[INFO] CLIENT {uuid} ATTEMPTED SIGNUP WITH username {user}")
        password = en.salt(data['password'])
        db.create_account()
        return await send_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'SIGNUP_OK'}})
    elif resp_captcha == False:
        return await send_packet(SESSIONS, ws, {'type':'STATUS','data':{'sig':'CAPTCHA_WRONG'}})

    

async def captcha(SESSIONS, SERVER_CREDS, ws, data):
    uuid = await identify_client(ws, SESSIONS)
    challenge = str(randint(100000,999999))
    data = ImageCaptcha().generate(challenge)
    image = data.getvalue()
    print('captcha image', image)
    packet = en.encrypt_packet({'type':'CAPTCHA', 'data':{'challenge':image}}, SESSIONS[uuid][1])
    await ws.send(packet)
    print(f"[INFO] GENERATED CAPTCHA FOR CLIENT {uuid} with CODE {challenge}")
    resp = await ws.recv()
    # handle possible INVALID_PACKET in next line 
    de_resp = pickle.loads(en.decrypt_packet(resp, SERVER_CREDS['server_eprkey']))
    de_resp = de_resp['data']['solved']
    print("CLIENT DERESP", de_resp)
    if int(de_resp) == int(challenge):
        return True
    else:
        return False

upacket_map = {
    'CONN_INIT':1,
    'CONN_ENCRYPT_C':2
}
packet_map = {
    'SIGNUP':signup,
    'LOGIN':3,
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

