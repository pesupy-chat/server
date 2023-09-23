from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from server_modules import i18n
from getpass import getpass
from os import urandom
from base64 import urlsafe_b64encode

def create_key_pair():
    private_key_d = ec.generate_private_key(ec.SECP256K1())
    public_key_d = private_key_d.public_key()
    private_key = private_key_d.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = public_key_d.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_key

def fernet_initkey(workingdir):
    passwd = ''
    while True:
        passwd = getpass(i18n.firstrun.passwd.input)
        confirm = getpass(i18n.firstrun.passwd.confirm)
        if passwd == confirm:
            break
        else:
            print(i18n.firstrun.passwd.retry)
    # Generate a Fernet key with the password and save the salt
    salt = urandom(16)
    with open(f"{workingdir}/creds/salt", "wb") as f:
        f.write(salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    key = urlsafe_b64encode(kdf.derive(bytes(passwd, 'utf-8')))
    key = Fernet(key)
    return key

def fermat_gen(workingdir):
    passwd = getpass("Enter Password:")
    with open(f"{workingdir}/creds/salt", "rb") as f:
        salt = f.read()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    key = urlsafe_b64encode(kdf.derive(bytes(passwd, 'utf-8')))
    key = Fernet(key)
    return key

def decrypt_server_privkey(fkey,workingdir):
    with open(f'{workingdir}/creds/pkey', "rb") as f:
        data = f.read()
    return fkey.decrypt(data)

def encrypt_packet(data, key):
    return key.encrypt(data)
def encrypt_chat(data, key):
    return key.encrypt(data)
def decrypt_packet(data, key):
    return key.decrypt(data)