import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.backends import default_backend

def hybrid_encrypt(public_key, message: bytes) -> bytes:
    # Генерация AES-ключа и IV
    aes_key = os.urandom(32)   # AES-256
    iv = os.urandom(16)

    # Шифрование сообщения AES (CBC + PKCS7)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()

    # Шифрование AES-ключа RSA (OAEP)
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Упаковка: [длина_ключа][ключ][iv][шифротекст]
    return (len(encrypted_aes_key).to_bytes(4, 'big') +
            encrypted_aes_key + iv + encrypted_message)

def hybrid_decrypt(private_key, encrypted_data: bytes) -> bytes:
    key_len = int.from_bytes(encrypted_data[:4], 'big')
    encrypted_aes_key = encrypted_data[4:4+key_len]
    iv = encrypted_data[4+key_len:4+key_len+16]
    encrypted_message = encrypted_data[4+key_len+16:]

    # Расшифровка AES-ключа
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Расшифровка сообщения
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

    # Удаление padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded_message) + unpadder.finalize()
