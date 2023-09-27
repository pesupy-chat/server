import os, sys
import asyncio
import websockets
from server_modules import encryption as en
from server_modules import db_handler as db
from cryptography.hazmat.primitives import serialization as s
import pickle

async def catch(websocket):
    con_id = await websocket.recv()
    SESSIONS[con_id] = [websocket, None, None] # ws, derived key, user_uid
    print(f"[INFO] {con_id} CONN_ESTABLISHED: {websocket}")
    print(f"SENDING PUBLIC KEY to {con_id}")
    await websocket.send(SERVER_CREDS['server_epbkey'])
    client_epbkey = await websocket.recv()
    client_epbkey = s.load_pem_public_key(client_epbkey)
    SESSIONS[con_id][1] = en.derive_key(
        SERVER_CREDS['server_eprkey'], client_epbkey, 'connection'
    )
    del client_epbkey
    try:
        while True:
            outpacket = await interpret(await websocket.recv(), websocket)
            outpacket = en.encrypt_packet(
                outpacket[1], SESSIONS[outpacket[0]][1]
            )
            await websocket.send(outpacket)
    except Exception as e:
        del SESSIONS[con_id]
        print(f"Client {con_id} disconnected due to\n\t\t",e)

async def interpret(packet, websocket):
    sender = await identify_client(websocket)
    dict = en.decrypt_packet(pickle.loads(packet), SESSIONS[sender][1])
    de_packet = pickle.loads(dict)
    de_packet['data'] = de_packet['data'] + ' ' + str(packet_no[0])
    print(f"[INFO] Server sent {de_packet} to {websocket.remote_address} [{sender}]")
    packet_no[0] += 1
    return [sender, de_packet] #handler(sender, type, data)

async def identify_client(websocket):
    return list(SESSIONS.keys())[[i[0] for i in list(SESSIONS.values())].index(websocket)]

async def main():
    async with websockets.serve(
        catch, host='', port=6969, 
        ping_interval=30, ping_timeout=None, close_timeout=None,
        max_size=10485760 ):
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    SESSIONS = {}
    SERVER_CREDS = {}
    workingdir = '/mnt/data/pesupy'
    db.decrypt_creds(en.fermat_gen(workingdir), workingdir)
    server_eprkey, server_epbkey = en.create_key_pair()
    SERVER_CREDS['server_eprkey'] = server_eprkey
    SERVER_CREDS['server_epbkey'] = en.ser_key_pem(server_epbkey, 'public')
    packet_no = {0:0}
    asyncio.run(main())