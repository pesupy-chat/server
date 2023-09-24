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

def create_key_pair():
    private_key_d = ec.generate_private_key(ec.SECP256K1())
    public_key_d = private_key_d.public_key()
    return private_key_d, public_key_d

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

def encrypt_packet(data, key):
    aesgcm = AESGCM(key)
    nonce = urandom(12)  # Unique nonce for each message
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return pickle.dumps({'nonce': nonce, 'ciphertext': ciphertext})

def de_packet(packet):
    return loads(packet.decode('utf-8').replace('"', "\\\"").replace("'", "\""))

def decrypt_packet(data, key):
    aesgcm = AESGCM(key)
    nonce = data['nonce']
    ciphertext = data['ciphertext']
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext