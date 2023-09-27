import os
import getpass
from i18n import firstrun
from . import encryption as e
from . import db_handler
import pickle 
from yaml import dump as dumpyaml
try: 
    from tkinter import filedialog
except:
    pass

def get_server_dir():
    while True:
        try:
            # Open GUI file picker if possible
            print(firstrun.savedata.gui)
            spath = filedialog.askdirectory()
        except:
            print(firstrun.savedata.nogui)
            spath = input()
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
            print("Previous Installation Detected! Please delete the files or choose another folder.")

    return spath

def save_db_credentials(fkey,workingdir):
    host = input('Enter MySQL/MariaDB Server IP Address: ')
    port = input('Enter MySQL/MariaDB Server Port (leave blank for 3306): ')
    user = input('Enter Username: ')
    if not port:
        port = 3306
    else:
        port = int(port)
    passwd = getpass.getpass('Enter Password: ')
    data = pickle.dumps({'host':host, 'port': port, 'user':user, 'passwd':passwd})
    with open(f'{workingdir}/creds/db', 'wb') as f:
        f.write(fkey.encrypt(data))

def main():
    print(firstrun.welcome_message)
    print(firstrun.setup_server_dir)
    workingdir = setup_server_dir()
    fkey = e.fernet_initkey(workingdir)
    save_db_credentials(fkey,workingdir)
    del fkey
    print(firstrun.security)
    db_handler.decrypt_creds(e.fermat_gen(workingdir), workingdir)
    print(firstrun.initialize_db)
    db_handler.initialize_schemas()
    with open('config.yml', 'w') as fi:
        config = {'working_directory': workingdir}
        fi.write(dumpyaml(config))



