import asyncio
import websockets
from server_modules import encryption as e
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from json import loads

async def catch(websocket):
    user_id = await websocket.recv()
    SESSIONS[user_id] = websocket
    print(f"[INFO] {user_id} CONN_ESTABLISHED: {websocket}")
    ## print("SENDING", CREDS['pubkey'])
    ## await websocket.send(CREDS['pubkey'])
    await websocket.send('CON_EST')
    ## client_epkey = await websocket.recv()
    ## shared_secret = CREDS['privkey'].exchange(ec.ECDH(), client_epkey)
    ## SESSIONS[user_id] = (SESSIONS[user_id], AESGCM(HKDF(
    ##    algorithm = hashes.SHA256(), length = 32,
    ##    salt = None, info = None).derive(shared_secret)))
    try:
        while True:
            await websocket.send(await interpret(await websocket.recv(), websocket))
    except Exception as e:
        del SESSIONS[user_id]
        print(f"Client {user_id} disconnected due to\n\t\t",e)

async def interpret(packet, websocket):
    ### print("LEN OF PACKET DATA",len(packet_data))
    # decrypt using SESSIONS[user_id][1] (derived key) but you have to get user_id from websocket (identify key of dict using SESSIONS[user_id][0])
    ## decrypted_data = asyncio.to_thread(loads(CREDS['privkey'].decrypt(packet_data).decode('utf8').replace("'", "\"")))
    de_packet = loads(packet.decode('utf8').replace("'", "\""))
    packet_type = de_packet['type'] ## await decrypted_data['type']
    packet_data = de_packet['data'] ## await decrypted_data['data']
    print(f"[INFO] Server sent {packet_type} to {websocket}")
    return packet_data

async def main():
    async with websockets.serve(catch, '', 6969):
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    SESSIONS = {}
    CREDS = {}
    workingdir = '/mnt/data/pesupy'
    with open(f'{workingdir}/public_key.pem', 'rb') as f:
        CREDS['pubkey'] = f.read()
    CREDS['privkey'] = s.load_pem_private_key(e.decrypt_server_privkey(e.fermat_gen(workingdir),workingdir), password = None)
    asyncio.run(main())