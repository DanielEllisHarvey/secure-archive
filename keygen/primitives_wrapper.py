from cryptography.hazmat.primitives.kdf import pbkdf2, hkdf
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.backends import openssl
import hmac
import hashlib

def aes_gcm_encrypt(key, iv, data):
    return Cipher(
        algorithms.AES256(key),
        modes.GCM(iv, min_tag_length=128),
        backend=openssl.backend
    ).encryptor().update(data)

def aes_gcm_decrypt(key, iv, ciphertext):
    return Cipher(
        algorithms.AES256(key),
        modes.GCM(iv, min_tag_length=128),
        backend=openssl.backend
    ).decryptor().update(ciphertext)

def one_hkdf(key, salt):
    return hkdf.HKDF(
        algorithm=hashes.SHA3_256(),
        length=32,
        salt=salt,
        backend=openssl.backend
    ).derive(key)

def one_pbkdf(passwd, salt):
    return pbkdf2.PBKDF2HMAC(
        algorithm=hashes.SHA3_256(),
        length=32,
        salt=salt,
        iterations=1000,
        backend=openssl.backend
    ).derive(bytes(passwd, "utf-8"))

def hmac_sha512(key, data):
    return hmac.new(key, data, hashlib.sha3_512)
