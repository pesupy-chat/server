import asyncio
import websockets
from cryptography.hazmat.primitives import serialization as s
from client_modules import encryption as e
from uuid import uuid4
import pickle
from sys import exit

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
    print(data) # handle here using type and data
    return None

async def main():
    uri = "ws://ilamparithi.ddns.net:6969"
    async with websockets.connect(uri, ping_interval=30) as websocket:
        print('wtf do you want to do?')
        print("0. Establish secure connection")
        print("1. Send epubkey to server")
        print("2. send packet")
        
        while True:
            ch = int(input('> '))
            if ch == 0:
                con_id = input("Enter VALID UUID")# str(uuid4())
                await websocket.send(con_id)
                try:
                    key = await websocket.recv()
                    pubkey = s.load_pem_public_key(key)
                    SERVER_CREDS['server_epbkey'] = pubkey
                    print("RECEIVED SERVER PUBLIC KEY")
                    SERVER_CREDS['derived_key'] = e.derive_key(
                        CLIENT_CREDS['client_eprkey'], pubkey, 'connection'
                    )
                except websockets.exceptions.ConnectionClosedError as err:
                    print("Disconected from Server! Error:\n",err)
                    exit()
            elif ch == 1:
                await websocket.send(CLIENT_CREDS['client_epbkey'])
            else:
                type = input('Enter Packet Type: ')
                data = eval(input("Enter Packet Data: "))
                await send_message(websocket, {'type':type, 'data':data})

SERVER_CREDS = {}
CLIENT_CREDS = {}

if __name__ == '__main__':
    client_eprkey, client_epbkey = e.create_key_pair()
    CLIENT_CREDS['client_eprkey'] = client_eprkey
    CLIENT_CREDS['client_epbkey'] = e.ser_key_pem(client_epbkey, 'public')
    asyncio.get_event_loop().run_until_complete(main())
    asyncio.get_event_loop().run_forever()
