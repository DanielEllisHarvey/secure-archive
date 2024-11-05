#!/usr/bin/env python3

#? This file is the setup for the initial key generation
from os import urandom
import random
import hmac
import hashlib
import json

working_dir = "~/.secarch"
master_key_file = "master"

keys_per_file = 128

master_key = urandom(32)
random_bytes = urandom(4096)

with open(working_dir+"/"+master_key_file, "wb") as mkey_file:
    mkey_file.write(master_key)
    mkey_file.close()

with open(working_dir+"/master_nonce", "wb") as nonce:
    nonce.write(random_bytes)
    nonce.close()

