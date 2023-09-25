import asyncio
import websockets
from cryptography.hazmat.primitives import serialization as s
from client_modules import encryption as e
from uuid import uuid4
import pickle

async def send_message(websocket, message):
    outpacket = e.encrypt_packet(
        pickle.dumps(message), SERVER_CREDS['derived_key']
    )
    await websocket.send(outpacket)
    response = await websocket.recv()
    return await handle_resp(response)

async def handle_resp(response):
    inpacket = e.decrypt_packet(pickle.loads(response), SERVER_CREDS['derived_key'])
    de_packet = pickle.loads(inpacket)
    type = de_packet['type']
    data = de_packet['data']
    print(data)
    return None

async def main():
    uri = "ws://ilamparithi.ddns.net:6969"
    async with websockets.connect(uri, ping_interval=30) as websocket:
        user_id = str(uuid4())
        await websocket.send(user_id)
        key = await websocket.recv()
        pubkey = s.load_pem_public_key(key)
        SERVER_CREDS['server_epbkey'] = pubkey
        print("RECEIVED SERVER PUBLIC KEY")
        SERVER_CREDS['derived_key'] = e.derive_key(
            CLIENT_CREDS['client_eprkey'], pubkey, 'connection'
        )
        await websocket.send(CLIENT_CREDS['client_epbkey'])
        while True:
            # message = eval(input("Enter packet: "))
            for i in range(0, 31):
                await send_message(websocket, {'type':'echo', 'data':f'{i}'})

SERVER_CREDS = {}
CLIENT_CREDS = {}

if __name__ == '__main__':
    client_eprkey, client_epbkey = e.create_key_pair()
    CLIENT_CREDS['client_eprkey'] = client_eprkey
    CLIENT_CREDS['client_epbkey'] = e.ser_key_pem(client_epbkey, 'public')
    asyncio.get_event_loop().run_until_complete(main())
    asyncio.get_event_loop().run_forever()
