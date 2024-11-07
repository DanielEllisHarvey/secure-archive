#!/usr/bin/env python3

import json
import getpass
import sys
import time
from primitives_wrapper import aes_gcm_decrypt, aes_gcm_encrypt, one_pbkdf, hmac_sha512
from os import urandom, getenv
from base64 import urlsafe_b64encode

home_dir = getenv("HOME")
config = json.loads(open(home_dir+"/.config/secarch/config.json", "r").read())

master_key = open(home_dir+config["working_dir"]+config["master_key_file"], "rb").read()
salt = open(home_dir+config["working_dir"]+config["salt_file"], "rb").read()
passwd_salt = open(home_dir+config["working_dir"]+config["passwd_salt_file"], "rb").read()

passwd = getpass.getpass("passwd: ")
decryption_key = one_pbkdf(passwd, passwd_salt)
master_key = aes_gcm_decrypt(key=decryption_key, iv=master_key[-32:], ciphertext=master_key[:-32])

file_byte_id = urandom(64)
file_id = urlsafe_b64encode(file_byte_id).decode()
file_data = open(sys.argv[1], "rb").read()

file_key_iv = urandom(32)
file_key_xor = file_byte_id.rjust(config["salt_length"], file_key_iv[-1:])
file_key = hmac_sha512(master_key, bytes(a ^ b for a, b in zip(salt, file_key_xor))).digest()
file_key_enc = aes_gcm_encrypt(decryption_key, file_key_iv, file_key)

file_name = sys.argv[1].replace(" ", "_")

with open(home_dir+config["working_dir"]+"index", "a") as index:
    index.write(
        file_name+" "+ # File name
        str(int(time.time()//1))+" "+ # Current time
        hmac_sha512(master_key, file_data+file_byte_id).hexdigest()[:32]+" "+ # File data integrity (256 bit)
        urlsafe_b64encode(file_key_enc+file_key_iv).decode()+" "+ # Password-encrypted file key
        file_id+"\n"
    )
    index.close()

file_enc_iv = urandom(32)
# if len(sys.argv) <= 2:
with open(home_dir+config["default_archive_dest_dir"]+file_name+".enc", "wb") as file:
    file.write(aes_gcm_encrypt(file_key[:32], file_enc_iv, file_data)+file_enc_iv)
    file.close()
# else:
#     with open(sys.argv[2]+".enc", "wb") as file:
#         file.write(aes_gcm_encrypt(file_key[:32], file_enc_iv, file_data)+file_enc_iv)
#         file.close()
