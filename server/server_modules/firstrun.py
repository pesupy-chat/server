import os
import getpass
from i18n_for_modules import firstrun
import encryption as e
import db_handler
try: 
    from tkinter import filedialog
except:
    pass


def setup_server_dir():
    try:
        # Open GUI file picker if possible
        print(firstrun.savedata.gui)
        spath = filedialog.askdirectory()
    except:
        print(firstrun.savedata.nogui)
        spath = input()
        while True:
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
    os.mkdir(f'{spath}/creds')

    return spath

def save_db_credentials(fkey,workingdir):
    host = input('Enter MySQL/MariaDB Server IP Address: ')
    user = input('Enter Username: ')
    passwd = getpass.getpass('Enter Password: ')
    data = bytes(str({'host':host, 'user':user, 'passwd':passwd}), 'utf-8')
    with open(f'{workingdir}/creds/db', 'wb') as f:
        f.write(fkey.encrypt(data))

def main():
    print(firstrun.welcome_message)
    workingdir = setup_server_dir()
    fkey = e.fernet_initkey(workingdir)
    save_db_credentials(fkey,workingdir)
    del fkey
    print(firstrun.security)
    db_handler.decrypt_creds(e.fermat_gen(workingdir), workingdir)
    print(firstrun.initialize_db)
    db_handler.initialize_schemas()

if __name__ == '__main__':
    main()




