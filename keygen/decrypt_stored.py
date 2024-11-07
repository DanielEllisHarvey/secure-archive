#!/usr/bin/env python3

from os import getenv
from sys import argv
import json
import getpass
import datetime
from primitives_wrapper import one_pbkdf, aes_gcm_decrypt
from base64 import urlsafe_b64decode

def relative_from_timestamp(n: int | str):
    if type(n) == str:
        n = int(n)
    time_delta = (datetime.datetime.now() - datetime.datetime.fromtimestamp(n)).total_seconds() // 1
    return (
        str(int(time_delta/(60*60*24))) + " day(s), " +
        str(int(time_delta/(60*60))%24) + " hour(s), " +
        str(int(time_delta/60)%60) + " minute(s), " +
        str(int(time_delta%60))+ " second(s) ago"
    )

home_dir = getenv("HOME")
config = json.loads(open(home_dir+"/.config/secarch/config.json", "r").read())

master_key = open(home_dir+config["working_dir"]+config["master_key_file"], "rb").read()
salt = open(home_dir+config["working_dir"]+config["salt_file"], "rb").read()
passwd_salt = open(home_dir+config["working_dir"]+config["passwd_salt_file"], "rb").read()

passwd = getpass.getpass("passwd: ")
decryption_key = one_pbkdf(passwd, passwd_salt)
master_key = aes_gcm_decrypt(key=decryption_key, iv=master_key[-32:], ciphertext=master_key[:-32])

file_index = open(home_dir+config["working_dir"]+"index", "r").readlines()

file_matches = list(file.split(" ") for index, file in enumerate(file_index) if file.split(" ")[0] == argv[1])
# print(file_matches)
human_readable_meta = list(
    list((
        str(index),
        file[0]+" ("+
        file[4][:5] +")",
        relative_from_timestamp(file[1])
    )) for index, file in enumerate(file_matches)
)

print("matches:\n" + str(human_readable_meta).replace("], ", ",\n").replace("[", "").replace("]", ""))
index = int(input("index: "))
file_data_enc = open(home_dir+config["default_archive_dest_dir"]+argv[1].replace(" ", "_")+".enc", "rb").read()

# print(file_matches)
print(urlsafe_b64decode(file_matches[index][3])[:-32], urlsafe_b64decode(file_matches[index][3])[-32:])
file_key = aes_gcm_decrypt(decryption_key, urlsafe_b64decode(file_matches[index][3])[-32:], urlsafe_b64decode(file_matches[index][3])[:-32])
file_data = aes_gcm_decrypt(file_key[:32], file_data_enc[-32:], file_data_enc[:-32])
print(file_data.decode())