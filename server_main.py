import os, sys
import asyncio
import websockets
from server_modules import firstrun
from server_modules import encryption as en
from server_modules import db_handler as db
from server_modules import packet_handler as p
import pickle
import i18n
from yaml import safe_load as loadyaml
from yaml import dump as dumpyaml


async def disconnect(ws, code, reason):
    print(f"[INFO] CLIENT {identify_client(ws)} DISCONNECTED due to",code,reason)
    await ws.close(code=code, reason=reason)
    return None

async def identify_client(websocket):
    global SESSIONS
    return list(SESSIONS.keys())[[i[0] for i in list(SESSIONS.values())].index(websocket)]

def check_missing_config(f, yaml, config):
    try:
        if yaml[config] is None:
            print(i18n.firstrun.prompt1+config)
            if config == 'working_directory':
                print(i18n.firstrun.prompt2)
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
            else:
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

async def interpret(packet, websocket):
    global SESSIONS
    try:
        sender = await identify_client(websocket)
    except:
        pass
    ds_packet = pickle.loads(packet)
    if 'nonce' in ds_packet.keys():
        try:
            de_packet = en.decrypt_packet(ds_packet, SESSIONS[sender][1])
        except:
            await disconnect(websocket, 1008, "Invalid Packet Structure")
            return 'CONN_CLOSED'
    elif 'type' in ds_packet.keys() and ds_packet['type'] not in p.packet_map.keys() and ds_packet['type'] in p.upacket_map.keys():
        de_packet = ds_packet
    elif ds_packet['type'] in p.packet_map.keys():
        await disconnect(websocket, 4004, f"The packet {ds_packet['type']} must be encrypted")
        return 'CONN_CLOSED'
    else:
        await disconnect(websocket, 1008, "Invalid Packet Structure")
        return 'CONN_CLOSED'
    return await p.handle(SESSIONS, SERVER_CREDS, de_packet, websocket) # return handler(sender, type, data)

async def catch(websocket):
    # Handle further incoming packets
    try:
        while True:
            result = await interpret(await websocket.recv(), websocket)
            if result == 'CONN_CLOSED':
                pass
            else:
                await websocket.send(result)
    # Handle disconnection due to any exception
    except Exception as err3:
        client = await identify_client(websocket)
        print(f"[INFO] CLIENT {client} DISCONNECTED due to\n\t",err3)
        del SESSIONS[client]
        return None

async def main(host, port):
    async with websockets.serve(
        catch, host=host, port=port, 
        ping_interval=30, ping_timeout=None, close_timeout=None,
        max_size=10485760 
    ):
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    SESSIONS = {}
    SERVER_CREDS = {}

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
        check_missing_config(f, yaml, 'working_directory')
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
    try:
        asyncio.run(main(host,port))
    except KeyboardInterrupt:
        print('\n[INFO] Goodbye!')
