import os, sys
import asyncio
import websockets
from server_modules import firstrun
from server_modules import encryption as en
from server_modules import db_handler as db
# from server_modules import packet_handler as p
from cryptography.hazmat.primitives import serialization as s
import pickle
import i18n
from yaml import safe_load as loadyaml
from yaml import dump as dumpyaml
from uuid import UUID


def check_missing_config(f, yaml, config):
    try:
        if yaml[config] is None:
            print(i18n.firstrun.prompt1+config)
            fill_missing_config(f, yaml, config)
    except KeyError:
        print(i18n.firstrun.prompt1+config)
        fill_missing_config(f, yaml, config)

def fill_missing_config(f, yaml, config):
    print(i18n.firstrun.fix_missing, config)
    yaml[config] = input('\n> ')
    if config in ['listen_port', 'another_int']:
        yaml[config] = int(yaml[config])
    f.seek(0)
    f.write(dumpyaml(yaml))

def is_valid_uuid(uuid):
    try:
        UUID(uuid, version=4)
    except ValueError:
        return False
    else:
        return True and uuid not in SESSIONS.keys()

async def identify_client(websocket):
    global SESSIONS
    return list(SESSIONS.keys())[[i[0] for i in list(SESSIONS.values())].index(websocket)]

async def catch(websocket):
    print(f"[INFO] Remote {websocket.remote_address} attempted connection")
    # Establish Connection
    try:
        con_id = await websocket.recv()
    except websocket.exceptions.ConnectionClosedOK as err1:
        print(f"[INFO] Remote {websocket.remote_address} gracefuly disconnected:",err1)
    if is_valid_uuid(con_id):
        SESSIONS[con_id] = [websocket, None, None] # ws, derived key, user_uid
    else:
        print(f"[INFO] CLIENT unestablished {websocket.remote_address} DISCONNECTED due to INVALID_UUID")
        await websocket.close(code = 1008, reason = "Connection UUID Invalid/Already in use")
        return None

    print(f"[INFO] {con_id} CONN_ESTABLISHED: {websocket.remote_address}")
    print(f"[INFO] SENDING PUBLIC KEY to {con_id}")

    # Encrypt Connection
    await websocket.send(SERVER_CREDS['server_epbkey'])
    try:
        client_epbkey = await websocket.recv()
        client_epbkey = s.load_pem_public_key(client_epbkey)
        SESSIONS[con_id][1] = en.derive_key(
            SERVER_CREDS['server_eprkey'], client_epbkey, 'connection'
        )
        print(f"[INFO] Derived key for {websocket.remote_address}")
        del client_epbkey
    # If client sends bullshit instead of its PEM serialized ephemeral public key
    except Exception as err2:
    #   await websocket.send({'type':'ERR', 'data':{'code':'INVALID_CONN_KEY'}})
        print(f"[INFO] CLIENT {con_id} {websocket.remote_address} DISCONNECTED due to INVALID_CONN_KEY:\n\t",err2)
        await websocket.close(code = 1003, reason = "Connection Ephemeral Public Key in invalid format")
        del SESSIONS[con_id]
        return None
    
    # Handle further incoming packets
    try:
        while True:
            outpacket = await interpret(await websocket.recv(), websocket)
            outpacket = en.encrypt_packet(
                outpacket[1], SESSIONS[outpacket[0]][1]
            )
            await websocket.send(outpacket)
    # Handle disconnection due to any exception
    except Exception as err3:
        print(f"[INFO] CLIENT {con_id} DISCONNECTED due to\n\t",err3)
        del SESSIONS[con_id]
        return None

async def main(host, port):
    async with websockets.serve(
        catch, host=host, port=port, 
        ping_interval=30, ping_timeout=None, close_timeout=None,
        max_size=10485760 
    ):
        await asyncio.Future()  # run forever

async def interpret(packet, websocket):
    global packet_no, SESSIONS
    sender = await identify_client(websocket)
    dict = en.decrypt_packet(pickle.loads(packet), SESSIONS[sender][1])
    de_packet = pickle.loads(dict)
    de_packet['data'] = de_packet['data'] + ' ' + str(packet_no[0])
    print(f"[INFO] Server sent {de_packet} to {websocket.remote_address} [{sender}]")
    packet_no[0] += 1
    return [sender, de_packet] # return handler(sender, type, data)

if __name__ == "__main__":
    SESSIONS = {}
    SERVER_CREDS = {}
    packet_no = {0:0}
    try:
        rootdir = os.path.dirname(os.path.abspath(__file__))
        print(i18n.log.tags.info+i18n.log.server_start.format(rootdir))
        f = open(f'{rootdir}/config.yml', 'r+')
        yaml = loadyaml(f.read())
        if not yaml:
            f.close()
            os.remove(f'{rootdir}/config.yml')
            print(i18n.firstrun.empty_config, i18n.firstrun.exit, end='\n')
            sys.exit()
        elif not yaml['working_directory']:
            print(i18n.firstrun.prompt1+'working_directory', i18n.firstrun.prompt2, sep='\n', end='\n')
            while True:
                choice = input("(Y / N) > ")
                if choice.lower() == 'y':
                    print(i18n.firstrun.exec)
                    f.close()
                    os.remove(f'{rootdir}/config.yml')
                    firstrun.main()
                    print(i18n.firstrun.exit)
                    sys.exit()
                elif choice.lower() == 'n':
                    fill_missing_config(f, yaml, 'working_directory')
                    break
        check_missing_config(f, yaml, 'listen_address')
        check_missing_config(f, yaml, 'listen_port')
        f.close()

    except FileNotFoundError as err:
        print(i18n.firstrun.config_not_found, i18n.firstrun.exec)
        firstrun.main()
        print(i18n.firstrun.exit)
        sys.exit()

    workingdir = yaml['working_directory']
    host, port = yaml['listen_address'], yaml['listen_port']
    try:
        db.decrypt_creds(en.fermat_gen(workingdir), workingdir)
    except Exception as w:
        print("Error while decrypting database credentials. Check your password")
        print(i18n.firstrun.exit)
        sys.exit()
    server_eprkey, server_epbkey = en.create_key_pair()
    SERVER_CREDS['server_eprkey'] = server_eprkey
    SERVER_CREDS['server_epbkey'] = en.ser_key_pem(server_epbkey, 'public')
    print("[INFO] SERVER ONLINE!")
    asyncio.run(main(host,port))