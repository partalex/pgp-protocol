import json
from base64 import b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

try:
    read_iv = "read from file"
    read_ct = "read from file"
    key = "read from file"
    iv = b64decode(read_iv)
    ct = b64decode(read_ct)
    cipher_decrypt = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher_decrypt.decrypt(ct), AES.block_size)
    print("The message was: ", pt)
except (ValueError, KeyError):
    print("Incorrect decryption")