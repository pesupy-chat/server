import os
import getpass
from i18n import firstrun
from . import encryption as e
import pickle 
from yaml import dump as dumpyaml
try: 
    from tkinter import filedialog
except:
    pass

class working_dir():
    workingdir = ''

def get_server_dir():
    while True:
        try:
            # Open GUI file picker if possible
            print(firstrun.savedata.gui)
            spath = filedialog.askdirectory()
        except:
            print(firstrun.savedata.nogui)
            spath = input().rstrip('/\\')
        finally:
            break
    return spath

def setup_server_dir():
    while True:
        while True:
            spath = get_server_dir()
            # Do nothing if folder exists
            if os.path.exists(spath) and os.path.isdir(spath):
                break
            # If either the path leads to a file or is not writable (or invalid)
            elif os.path.exists(spath) and not os.path.isdir(spath):
                spath = input(f"{firstrun.savedata.not_a_dir}:\n")
            elif not os.path.exists(spath):
                print(firstrun.savedata.creating, end=' ')
                try:
                    os.mkdir(spath)
                except OSError as e:
                    print(f"{firstrun.savedata.error}:\n{e}")
                    spath = input(f"{firstrun.savedata.input_writable}:\n")
                else:
                    print(firstrun.savedata.created)
                    break
        if not os.path.exists(f'{spath}/creds'):
            os.mkdir(f'{spath}/creds')
            break
        elif os.path.exists(f'{spath}/creds'):
            print(firstrun.savedata.data_exists)

    return spath

def save_db_credentials(fkey,workingdir):
    host = input(firstrun.database.host)
    port = input(firstrun.database.port)
    user = input(firstrun.database.user)
    if not port:
        port = 3306
    else:
        port = int(port)
    passwd = getpass.getpass(firstrun.database.passwd)
    data = pickle.dumps({'host':host, 'port': port, 'user':user, 'passwd':passwd})
    with open(f'{workingdir}/creds/db', 'wb') as f:
        f.write(fkey.encrypt(data))

def save_queue_keypair(fkey, workingdir):
    prkey, pubkey = e.create_rsa_key_pair()
    pem_prkey, pem_pubkey = e.ser_key_pem(prkey, 'private'), e.ser_key_pem(pubkey, 'public')
    en_pem_prkey = fkey.encrypt(pem_prkey)
    with open(f'{workingdir}/creds/queue_privatekey', 'wb') as f:
        f.write(en_pem_prkey)
    with open(f'{workingdir}/creds/queue_publickey', 'wb') as f:
        f.write(pem_pubkey)

def main():
    print(firstrun.welcome_message)
    print(firstrun.setup_server_dir)
    workingdir = setup_server_dir()
    setattr(working_dir, 'workingdir', workingdir)
    fkey = e.fernet_initkey(workingdir)
    save_db_credentials(fkey, workingdir)
    save_queue_keypair(fkey, workingdir)
    del fkey
    host = input("Enter Server Listen Address: ")
    port = int(input("Enter Server Listen Port: "))
    with open(f'{os.path.dirname(os.path.abspath(__file__))}/../config.yml', 'w') as fi:
        config = {'working_directory': workingdir, 'listen_address': host, 'listen_port': port}
        fi.write(dumpyaml(config))




