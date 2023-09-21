import os
import sys
import getpass
import base64
from i18n import firstrun
from encryption import create_key_pair
import db_handler
try: 
    from tkinter import filedialog
except:
    pass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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
                spath = input(f"{firstrun.savedata.not_writable}:\n")
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

def setup_server_keys(workingdir):
    privkey, pubkey = create_key_pair()
    with open(f'{workingdir}/public_key.pem', 'wb') as f:
        f.write(pubkey)
    return privkey

def fernet_initkey(workingdir):
    passwd = ''
    while True:
        passwd = getpass.getpass(firstrun.passwd.input)
        confirm = getpass.getpass(firstrun.passwd.confirm)
        if passwd == confirm:
            break
        else:
            print(firstrun.passwd.retry)
    # Generate a Fernet key with the password and save the salt
    salt = os.urandom(16)
    with open(f"{workingdir}/creds/salt", "wb") as f:
        f.write(salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(bytes(passwd, 'utf-8')))
    key = Fernet(key)
    return key

def fermat_gen(workingdir):
    passwd = getpass.getpass("Enter Password:")
    with open(f"{workingdir}/creds/salt", "rb") as f:
        salt = f.read()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(bytes(passwd, 'utf-8')))
    key = Fernet(key)
    return key

def encrypt_server_privkey(fkey,pkey,workingdir):
    encrypted_data = fkey.encrypt(pkey)
    # Write the encrypted data to a new file.
    with open(f'{workingdir}/creds/pkey', "wb") as f:
        f.write(encrypted_data)

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
    fkey = fernet_initkey(workingdir)
    print(firstrun.keypair_setup)
    encrypt_server_privkey(fkey,setup_server_keys(workingdir),workingdir)
    save_db_credentials(fkey,workingdir)
    del fkey
    print(firstrun.security)
    db_handler.decrypt_creds(fermat_gen(workingdir), workingdir)
    print(firstrun.initialize_db)
    db_handler.initialize_schemas()

if __name__ == '__main__':
    main()




