from uuid import UUID
import asyncio
import pickle
from . import encryption as en
from uuid import UUID
from cryptography.hazmat.primitives import serialization as s

async def identify_client(websocket, SESSIONS):
    return list(SESSIONS.keys())[[i[0] for i in list(SESSIONS.values())].index(websocket)]

async def disconnect(ws, code, reason):
    print(f"[INFO] CLIENT {ws.remote_address} DISCONNECTED due to",code,reason)
    await ws.close(code=code, reason=reason)
    return None

async def establish_conn(SESSIONS, SERVER_CREDS, websocket, data):
    print(f"[INFO] Remote {websocket.remote_address} attempted connection")
    try:
        uuid = UUID(data, version=4)
    except ValueError:
        await websocket.close(code = 1008, reason = "Connection UUID Invalid")
        return None
    if uuid in SESSIONS.keys():
        await websocket.close(code = 1008, reason = "Connection UUID Already in use")
        return None
    SESSIONS[uuid] = [websocket, None, None] # ws, derived key, user_uid

    print(f"[INFO] {uuid} CONN_INIT: {websocket.remote_address}")
    print(f"[INFO] SENDING PUBLIC KEY to {uuid}")

    # Encrypt Connection
    await websocket.send(pickle.dumps({'type':'CONN_ENCRYPT_S','data':SERVER_CREDS['server_epbkey']}))
    try:
        client_epbkey = pickle.loads(await websocket.recv())
        try:
            client_epbkey = s.load_pem_public_key(client_epbkey['data'])
        except Exception as e:
            print(f"[INFO] CLIENT un-established {websocket.remote_address} DISCONNECTED due to INVALID_PACKET")
            await websocket.close(code = 1008, reason = "Invalid packet structure")
            return None
        
        SESSIONS[uuid][1] = en.derive_key(
            SERVER_CREDS['server_eprkey'], client_epbkey, 'connection'
        )
        print(f"[INFO] Derived key for {websocket.remote_address}")
        del client_epbkey
        return en.encrypt_packet(
            pickle.dumps({'type':'STATUS', 'data':{'sig':'CONN_OK'}}),
            SESSIONS[uuid][1],
            )
    # If client sends bullshit instead of its PEM serialized ephemeral public key
    except Exception as err2:
        print(f"[INFO] CLIENT {uuid} {websocket.remote_address} DISCONNECTED due to INVALID_CONN_KEY:\n\t",err2)
        await websocket.close(code = 1003, reason = "Connection Ephemeral Public Key in invalid format")
        del SESSIONS[uuid]
        return None

async def signup(SESSIONS, SERVER_CREDS, ws, data):
    user = data['user']
    email = data['email']
    fullname = data['fullname']
    password = data['password']
    de_packet = {'type':'STATUS', 'data':{'sig':'NEW_ACC_OK', 'sigvresp':[user,email,fullname,password]}}
    uuid = list(SESSIONS.keys())[[i[0] for i in list(SESSIONS.values())].index(ws)]
    en_packet = en.encrypt_packet(pickle.dumps(de_packet), SESSIONS[uuid][1])
    print(f"[INFO] CLIENT {uuid} ATTEMPTED SIGNUP WITH username {user}")
    return en_packet

upacket_map = {
    'CONN_INIT':1,
    'CONN_ENCRYPT_C':2
}
packet_map = { 
    'SIGNUP':signup,
    'S_CAPTCHA':2,
    'LOGIN':3,
    'CHAT_ENCRYPT_C':4,
    'AUTHENTICATE':6,
    'CREATE_ROOM':5,
    'CHAT_ACTION':7,
    'ALTER_ROOM':8,
    'LOGOUT':9
}

async def handle(SESSIONS, SERVER_CREDS, ds_packet, ws):
    if 'nonce' in ds_packet.keys():
        sender = await identify_client(ws, SESSIONS)
        try:
            de_packet = en.decrypt_packet(ds_packet, SESSIONS[sender][1])
            de_packet = pickle.loads(de_packet)
        except:
            await disconnect(ws, 1008, "Invalid Packet Structure")
            return 'CONN_CLOSED'
    elif 'type' in ds_packet.keys() and ds_packet['type'] not in packet_map.keys() and ds_packet['type'] in upacket_map.keys():
        de_packet = ds_packet
    elif ds_packet['type'] in packet_map.keys():
        await disconnect(ws, 4004, f"The packet {ds_packet['type']} must be encrypted")
        return 'CONN_CLOSED'
    else:
        await disconnect(ws, 1008, "Invalid Packet Structure")
        return 'CONN_CLOSED'
    type = de_packet['type']
    data = de_packet['data']
    if type == 'CONN_INIT':
        return await establish_conn(SESSIONS, SERVER_CREDS, ws, data)
    else:
        func = packet_map[type]
        return await func(SESSIONS, SERVER_CREDS, ws, data)

