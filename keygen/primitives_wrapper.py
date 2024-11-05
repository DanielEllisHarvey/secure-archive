from cryptography.hazmat.primitives.kdf import pbkdf2, hkdf
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
import hmac
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

def one_hkdf(key, salt):
    return hkdf.HKDF(
        algorithm=hashlib.sha256,
        length=256,
        salt=salt
    ).derive(key)

def one_pbkdf(passwd, salt):
    return pbkdf2.PBKDF2HMAC(
        algorithm=hashlib.sha3_256,
        length=256,
        salt=salt,
        iterations=1000
    ).derive(bytes(passwd, "utf-8"))
    
def hmac_sha512(key, data):
    return hmac.new(key, data, hashlib.sha3_512)