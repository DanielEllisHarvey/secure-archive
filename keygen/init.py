#!/usr/bin/env python3

#? This file is the setup for the initial key generation
from os import urandom, getenv
import json
import getpass
from primitives_wrapper import one_pbkdf, aes_gcm_encrypt

home_dir = getenv("HOME")
config = json.loads(open(home_dir+"/.config/secarch/config.json", "r").read())

passwd_salt = urandom(config["passwd_salt_length"])
master_key = urandom(32)
master_key_iv = urandom(32)
salt_iv = urandom(32)
salt = urandom(config["salt_length"])

choice = input("This action will overwrite the current keys, would you like to continue? (y/N): ")
if choice not in "yY": exit()

passwd = getpass.getpass("passwd: ")
encryption_key = one_pbkdf(passwd, passwd_salt)
master_key_enc = aes_gcm_encrypt(encryption_key, master_key_iv, master_key)
salt_enc = aes_gcm_encrypt(encryption_key, salt_iv, salt)

with open(home_dir+config["working_dir"]+config["passwd_salt_file"], "wb") as pass_salt_file:
    pass_salt_file.write(passwd_salt)
    pass_salt_file.close()

with open(home_dir+config["working_dir"]+config["master_key_file"], "wb") as mkey_file:
    mkey_file.write(master_key_enc+master_key_iv)
    mkey_file.close()

with open(home_dir+config["working_dir"]+config["salt_file"], "wb") as salt:
    salt.write(salt_enc+salt_iv)
    salt.close()
