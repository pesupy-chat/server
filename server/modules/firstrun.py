import os
import getpass
from encryption import create_key_pair
from tkinter import filedialog
import cryptography.fernet


def setup_server_dir():
    try:
        # Open GUI file picker if possible
        print("Choose a folder for the server to save its data in")
        spath = filedialog.askdirectory()
    except:
        print("Cannot open file chooser! Enter the path manually:")
        spath = input()
        while True:
            # Do nothing if folder exists
            if os.path.exists(spath) and os.path.isdir(spath):
                break
            # If either the path leads to a file or is not writable (or invalid)
            elif os.path.exists(spath) and not os.path.isdir(spath):
                spath = input("Please enter path to a folder!:\n")
            elif not os.path.exists(spath):
                print("Folder not found, creating...", end=' ')
                try:
                    os.mkdir(spath)
                except OSError as e:
                    print(f"An error occurred:\n{e}")
                    spath = input("Please enter a writeable folder path:\n")
                else:
                    print("Created!")
                    break
    return spath


def setup_server_keys():
    global workingdir
    privkey, pubkey = create_key_pair()
    with open(f'{workingdir}/private_key.pem', 'wb') as f:
        f.write(privkey)
    with open(f'{workingdir}/public_key.pem', 'wb') as f:
        f.write(pubkey)


def encrypt_server_privkey():
    global workingdir
    while True:
        keyw = getpass("Enter the server's launch password: ")
        confirm = getpass("Enter it again to confirm: ")
        if keyw == confirm:
            break
        else:
            print("Passwords do not match!")
    # Generate a Fernet key and encrypt the created private key with the password
    key = cryptography.fernet.Fernet(keyw.encode())
    with open(f'{workingdir}/key.pem', "rb+") as f:
        data = f.read()
    encrypted_data = key.encrypt(data)
    # Write the encrypted data to a new file.
    with open(f'{workingdir}/DO NOT DELETE', "wb") as f:
        f.write(encrypted_data)
