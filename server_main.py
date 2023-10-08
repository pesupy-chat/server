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
    if config in ['listen_port', 'any_other_int_type_config']:
        yaml[config] = int(yaml[config])
    f.seek(0)
    f.write(dumpyaml(yaml))

async def interpret(packet, websocket):
    global SESSIONS
    try:
        sender = await p.identify_client(websocket, SESSIONS)
    except:
        pass
    return await p.handle(SESSIONS, SERVER_CREDS, packet, websocket) # return handler(sender, type, data)

async def catch(websocket):
    # Handle incoming packets
    try:
        while True:
            result = await interpret(await websocket.recv(), websocket)
            if result == 'CONN_CLOSED':
                pass
            else:
                await websocket.send(result)
                print('Sent', result)
    # Handle disconnection due to any exception
    except Exception as err3:
        client = await p.identify_client(websocket, SESSIONS)
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
        print("Error while decrypting database credentials. Check your password\n",w)
        print(i18n.firstrun.exit)
        sys.exit()

    server_eprkey, server_epbkey = en.create_conn_key_pair()
    SERVER_CREDS['server_eprkey'] = server_eprkey
    SERVER_CREDS['server_epbkey'] = en.ser_key_pem(server_epbkey, 'public')

    print("[INFO] SERVER ONLINE!")
    try:
        asyncio.run(main(host,port))
    except KeyboardInterrupt:
        print('\n[INFO] Goodbye!')
        sys.exit()























"""
this server is powered by this cat -- https://rory.cat
,,,,...,,,***//////////(/////****,,,,,,***,,,,,,,,,,****//////////((#####(((////////////////////////////////
........,,****/////((//////////*****,,,,,,,,,,,,,,******//////////(######(((////////////////////////////////
...... ..,***///(//(((((((/////////**********,********///////////(((######((((///******///***///////////////
......   .,*%((##%#((((/(/(((((((((((//////*****/////////////////(((#########((//***,,*******///////////////
,,.........,((((#%%#(%#(((((((((((##(((///////////////**/////////((####%%%####(//**,,,,,,**/////////////////
,,,,..,,,,,*((///((####(#(((((((######(((////////////*********////((########(((//********/&#(((////////////(
,,,,,,,,,,,**#(/(#####%##(/((//((####(((/////////////******///////((((####((((//****/(#%((((/(/*/////(((((((
,,,,,,,,,,****#(((#########((/((/((((((///*///////////////((((((((((((((((((////((((%(((((//(***////((((((((
,,,,,,,,*,,,***#((((#((######(/*,/#(##/****///(((((((((#####%%%%##((((###((((//*/#((((((#(#(/**////(((((((((
,,,*************#(/(((#######((/*,*,*(/****/**/*****,**,,**//**/((((//****,*,*#(//(/(((((#(((//////(((((((((
*****************((((/((((((#(//(*,*,**/***,,****,***,*,,*,****,***/*/**/(/,,,*///((((###%###(((/////(((((((
************,******(((///*//((##/**,**/**,,,,,*(/%/***,,,,,,,,,,,,***,*,,,,,,***////((#%%%%%###(((////(((((#
********,,,,,,,,,**/(((////(((///*****,/***,/((%#&/**,,,***,,,,,,*..,,,.,,,,,***///(/(#%%%%%%###(((//(((((##
,,,,,,,,,,,,,,,,,,,*(#(**,/////******/**(//#&%#@&&#**,***,/*,*,,*,,.,,,****(/((////**(%%&%%%%%##(((///((((##
,,,,..............,,*%(//**/*/*//(//#(#(#((%&&&@@&%*,/,,,*/,,,.**,***,,,,,,***///***/#&&&%%%%%##((/////(((##
,,,..................,(/*/******(//*(%%(##%&@@@@@&%((/,,*//,***/(#/*****,,,,,*,*,,,,*%&&&&&%%%##((/////((((#
*,,,,,,..............,(/*,,**((((//*/(#(//&&&&&&&&&%#//**//*,,*((****/////,,,,,,,,**#%&&&&&%%%%##((///(((((#
***,,,,,,,,,.......,*/**///*//////////****(#%%%%&%%%%#//****,*///*****(((*/*,,,,,,*//#%&&&&%%%%##(((//(((((#
******,,,,,,,.....,,*******,*,. ,(. .   .*/#%%%%%&%%%%#(*****,,..   ...,******//*,,*/(%%&&&%%%%###((//(((((#
********,,,,,,,,,,,/**,,*//(//* *,.   .,.,.#%%%%&%%%%%%%#(/, ...    .,,.,***,,*******/%%%%%%%%%%##((///((((#
*********,,,,,,,,,***,,////***//* ,*,,,,...#&&&&&&%%%%%%%/..,,/*,  ,,..//*///*,,,,***/(%%%%%%%%%##((///(((((
**************************,,,,***/((((/(#,,%&&&&&&&&&&&%(,....   .,**,,.,******,,,,,,**(%%%%%%%###(((//(((((
*****************//*///****,,,,,/(#%&&&&&&&&&&&&&&&&&%&&%/,/(#(/**/*,..,,,,,,**/*/*,,,,*/(########(((///((((
****************//(((#((///,,,,*((%&&&&&&&&&&&&@@&&&&&&%%&&&&&&%%%#/*,,,**,*///*/((/*,,*/###%%#((((##%######
*****************//(((##(////***#%&&&&&&&&&&&&&&&&&&&%%%%%&&&&%%%%%(*,*//((((///*****,,*(((((#%#(///**//(###
*******************/###((((((###%%%%%%&&&&&%&%%%%%%%%%#%&&%%%%%%%%####(/((##((//**,*,**(#((/*//((/******//(#
********************/(#########%%%%&&&&%&&&#/*#(/(/*,,(#%&&%%%%%%%%%%##(//(((/****/**/((///*****/*********//
/////////************/(%%######%%%%%%%%%%%%%%%//**./####%##%#%%%%%%%%####((((#(((((##%%%(////***//*,,,*,,,*/
/////////**/*********//(%%####%##%%%%####%%%####//(######%%%%%###%#%%%%%%%######%%%%%%###/**,,,,****,,,,,,**
////***************///(%&&%%%%%%###%%#########(/,,*(((############%%%%%%%%%%%%%%%%%%%##(/*,,*/*******,,,,,**
*********,,*******//((%&@&&&%%%%%%###%%%##(#((#((((//**/////(##########%%%%%%%&&&&&&%%%(,,,***,*,,***,,,,**/
*****************///(%&&&&&%%%%%%%%######%%%###((((################%%%%%%%&&&&&&&&&%#(**/*..***,,,,,,,.,,***
******************/(#&&&&&%%%%%%%%%%%%%######%%%#############%%%%%%%%%%&&&&&&&&%%%%##%/,*,*/,,.,,,,,,,,,**//
*************,,***/(%&&&&&%%%%%%%%%%%%%%%%%%%%##%%#%%###%%%#%%%%%%%%%%%%%%%%%%%%(((//**/(*,,**,...,,,,,,*//(
,,********,,,,,,**/(%&&&&%%%%%%%%%%%%%%%%%%%%%%%%%#%%%%%%%%%%%%%%%%%%%%%%%#%#(/(*,/**,,,,,*,,.,*,.,,,,***///
"""