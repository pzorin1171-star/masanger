import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

KEY_DIR = "keys"
PRIVATE_KEY_FILE = os.path.join(KEY_DIR, "private_key.pem")

def ensure_key_dir():
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)

def generate_rsa_keypair():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

def save_private_key(private_key, filename=PRIVATE_KEY_FILE):
    ensure_key_dir()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as f:
        f.write(pem)

def load_private_key(filename=PRIVATE_KEY_FILE):
    with open(filename, 'rb') as f:
        pem = f.read()
    return serialization.load_pem_private_key(
        pem,
        password=None,
        backend=default_backend()
    )

def get_public_key_der(private_key):
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def get_public_key_from_der(der_bytes):
    return serialization.load_der_public_key(
        der_bytes,
        backend=default_backend()
    )

def load_or_generate_keys():
    if os.path.exists(PRIVATE_KEY_FILE):
        return load_private_key()
    else:
        private_key = generate_rsa_keypair()
        save_private_key(private_key)
        return private_key
