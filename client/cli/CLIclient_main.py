import asyncio
import websockets
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from uuid import uuid4

async def send_message(websocket, message):
    # encrypt using derived key and send as dict with nonce and ciphertext
    ## encrypted = SERVER_CREDS['pubkey'].encrypt(bytes(str(message),'utf-8'))
    await websocket.send(str(message).encode()) ## websocket.send(encrypted)
    response = await websocket.recv()
    return await handle_resp(response)

async def handle_resp(response):
    print(response)
    return None

async def main():
    uri = "ws://ilamparithi.ddns.net:6969"
    async with websockets.connect(uri) as websocket:
        user_id = str(uuid4())
        await websocket.send(user_id)
        if await websocket.recv() == 'CON_EST':
            print("CONNECTION ESTABLISHED")
        ## key = await websocket.recv()
        ## pubkey = s.load_pem_public_key(key.encode())
        ## SERVER_CREDS['pubkey'] = pubkey
        ## print("RECEIVED", SERVER_CREDS['pubkey'])
        ## CLIENT_CREDS['ephemeral_private_key'] = ec.generate_private_key(ec.SECP256K1())
        ## CLIENT_CREDS['ephemeral_public_key'] = CLIENT_CREDS['ephemeral_private_key'] .public_key()
        ## CLIENT_CREDS['shared_secret'] = CLIENT_CREDS['ephemeral_private_key'].exchange(ec.ECDH(), server_public_key)
        while True:
            message = eval(input("Enter packet: "))
            await send_message(websocket, message)

SERVER_CREDS = {}
CLIENT_CREDS = {}

if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
    asyncio.get_event_loop().run_forever()
