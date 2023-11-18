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
    try:
        print(firstrun.savedata.gui)
        return filedialog.askdirectory()
    except:
        print(firstrun.savedata.nogui)
        return input().rstrip('/\\')

def create_directory(path):
    try:
        os.mkdir(path)
        print(firstrun.savedata.created)
    except OSError as e:
        print(f"{firstrun.savedata.error}:\n{e}")
        return False
    return True

def setup_server_dir():
    while True:
        spath = get_server_dir()
        if os.path.exists(spath) and os.path.isdir(spath):
            pass
        elif os.path.exists(spath) and not os.path.isdir(spath):
            spath = input(f"{firstrun.savedata.not_a_dir}:\n")
        elif not os.path.exists(spath):
            if not create_directory(spath):
                spath = input(f"{firstrun.savedata.input_writable}:\n")
                continue

        creds_path = f'{spath}/creds'
        if not os.path.exists(creds_path):
            if create_directory(creds_path):
                break
        else:
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

def main():
    print(firstrun.welcome_message)
    print(firstrun.setup_server_dir)
    workingdir = setup_server_dir()
    setattr(working_dir, 'workingdir', workingdir)
    fkey = e.fernet_initkey(workingdir)
    save_db_credentials(fkey, workingdir)
    del fkey
    host = input("Enter Server Listen Address: ")
    port = int(input("Enter Server Listen Port: "))
    with open(f'{os.path.dirname(os.path.abspath(__file__))}/../config.yml', 'w') as fi:
        config = {'working_directory': workingdir, 'listen_address': host, 'listen_port': port}
        fi.write(dumpyaml(config))




