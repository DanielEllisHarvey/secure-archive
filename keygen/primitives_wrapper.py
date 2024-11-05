from cryptography.hazmat.primitives.kdf import pbkdf2
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
import hashlib

def aes_gcm_encrypt(key, iv, data):
    return Cipher(
        algorithms.AES256(key),
        modes.GCM(iv, min_tag_length=128)
    ).encryptor().update(data)

def aes_gcm_decrypt(key, iv, ciphertext):
    return Cipher(
        algorithms.AES256(key),
        modes.GCM(iv, min_tag_length=128)
    ).decryptor().update(ciphertext)

def one_pbkdf(passwd, salt):
    return pbkdf2.PBKDF2HMAC(
        algorithm=hashlib.sha3_256,
        length=256,
        salt=salt,
        iterations=1000
    ).derive(bytes(passwd, "utf-8"))