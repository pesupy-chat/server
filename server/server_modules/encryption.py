from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from getpass import getpass
from os import urandom
from base64 import urlsafe_b64encode
from json import loads
import pickle
from binascii import hexlify
import i18n

def create_key_pair():
    private_key_d = ec.generate_private_key(ec.SECP256K1())
    public_key_d = private_key_d.public_key()
    return private_key_d, public_key_d

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
    passwd = getpass("Enter Password: ")
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

def derive_key(eprkey, epbkey, keyinfo):
    shared_key = eprkey.exchange(
        ec.ECDH(), epbkey)
    # Perform key derivation.
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=keyinfo.encode(),
    ).derive(shared_key)
    return derived_key

def ser_key_pem(key, type: str):
    if type == 'public':
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    elif type == 'private':
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

def encrypt_packet(data, key):
    data = pickle.dumps(data)
    aesgcm = AESGCM(key)
    nonce = urandom(12)  # Unique nonce for each message
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return pickle.dumps({'nonce': nonce, 'ciphertext': ciphertext})

def decrypt_packet(data, key):
    aesgcm = AESGCM(key)
    nonce = data['nonce']
    ciphertext = data['ciphertext']
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext