#!/usr/bin/env python3

from os import getenv
import json
import getpass
from primitives_wrapper import one_pbkdf, aes_gcm_decrypt


home_dir = getenv("HOME")
config = json.loads(open(home_dir+"/.config/secarch/config.json", "r").read())

master_key = open(home_dir+config["working_dir"]+config["master_key_file"], "rb").read()
salt = open(home_dir+config["working_dir"]+config["salt_file"], "rb").read()
passwd_salt = open(home_dir+config["working_dir"]+config["passwd_salt_file"], "rb").read()

passwd = getpass.getpass("passwd: ")
decryption_key = one_pbkdf(passwd, passwd_salt)
master_key = aes_gcm_decrypt(key=decryption_key, iv=master_key[-32:], ciphertext=master_key[:-32])

file_index = open(home_dir+config["working_dir"]+"index", "r").readlines()
filenames = list(file.split(" ")[0] for index, file in enumerate(file_index))
print(filenames)