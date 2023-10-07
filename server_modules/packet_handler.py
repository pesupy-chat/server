from uuid import UUID
import asyncio
import pickle
from . import encryption as en
from uuid import UUID
from cryptography.hazmat.primitives import serialization as s

upacket_map = {
    'CONN_INIT':1,
    'CONN_ENCRYPT_C':2
}
packet_map = { 
    'SIGNUP':1,
    'S_CAPTCHA':2,
    'LOGIN':3,
    'CHAT_ENCRYPT_C':4,
    'AUTHENTICATE':6,
    'CREATE_ROOM':5,
    'CHAT_ACTION':7,
    'ALTER_ROOM':8,
    'LOGOUT':9
}

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

async def handle(SESSIONS, SERVER_CREDS, packet, ws):
    type = packet['type']
    data = packet['data']
    if type == 'CONN_INIT':
        return await establish_conn(SESSIONS, SERVER_CREDS, ws, data)
    else:
        func = packet_map[type]
        return await func(SESSIONS, SERVER_CREDS, ws, data)
