from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import padding as spadding
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
from secrets import token_hex
from getpass import getpass
from os import urandom
from base64 import urlsafe_b64encode
import pickle
import i18n
import jwt
import datetime

def create_rsa_key_pair():
    # Generate a 2048-bit RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    # Derive the public key
    public_key = private_key.public_key()
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

def fernet_gen(workingdir):
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
def deser_pem(key, type):
    if type == 'public':
        return serialization.load_pem_public_key(key)
    elif type == 'private':
        return serialization.load_pem_private_key(key, password=None)

def encrypt_packet(data, pubkey):
    data = pickle.dumps(data)
    # Generate symmetric key and encrypt it
    skey = urandom(32)
    encrypted_skey = pubkey.encrypt(
        skey,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    # Encrypt packet data with symmetric key
    cbc = urandom(16)
    # Add the padding to the data
    padder = spadding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    # Encrypting the padded_data
    cipher = Cipher(algorithms.AES(skey), modes.CBC(cbc))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return pickle.dumps({'skey':encrypted_skey, 'cbc':cbc, 'ciphertext':ciphertext})

def decrypt_packet(encrypted_data, privkey):
    try:
        # Decrypt our symmetric key
        packet = pickle.loads(encrypted_data)
        de_skey = privkey.decrypt(
            packet['skey'],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        # And then use the decrypted symmetric key to decrypt our data

        cipher = Cipher(algorithms.AES(de_skey), modes.CBC(packet['cbc']))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(packet['ciphertext']) + decryptor.finalize()

        # Create an unpadder object
        unpadder = spadding.PKCS7(algorithms.AES.block_size).unpadder()
        # Remove the padding from the data
        data = unpadder.update(decrypted_data) + unpadder.finalize()
        return pickle.loads(data)
    except Exception as error:
        return {'type':'decrypt_error','data':f'{error}'}
    
def salt_pwd(password):
    pwd = password.encode()
    salt = urandom(16)

    # Derive a key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
        backend=default_backend()
    )
    key = urlsafe_b64encode(kdf.derive(pwd))

    # Store the salt and key in your database
    return pickle.dumps({'salt':salt, 'key':key})

def db_check_pwd(pwd, saltedpwd):
    salted_pwd = pickle.loads(saltedpwd)
    print(f"[DEBUG] {salted_pwd}")
    salt, key = salted_pwd['salt'], salted_pwd['key']
    password = pwd.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
        backend=default_backend()
    )
    provided_key = urlsafe_b64encode(kdf.derive(password))

    # Check if the provided key matches the stored key
    if provided_key == key:
        return True
    else:
        return False
    
def gen_token(user, validity):
    """
    `validity` in days
    """
    secret = token_hex(32)
    payload = {
        "sub": user,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days = validity)
    }
    access_token = jwt.encode(payload, secret, algorithm="HS256")
    return (secret, access_token)

def validate_token(key, token, user):
    try:
        decoded_token = jwt.decode(token, key, algorithms=["HS256"])
    except:
        return 'TOKEN_INVALID'
    timenow = datetime.datetime.utcnow()
    if decoded_token['sub'] == user and timenow < decoded_token['exp']:
        return 'TOKEN_OK'
    elif decoded_token['sub'] == user and timenow > decoded_token['exp']:
        return 'TOKEN_EXPIRED'
    elif decoded_token['sub'] != user:
        return 'TOKEN_INVALID'
    else:
        return 'TOKEN_INVALID'