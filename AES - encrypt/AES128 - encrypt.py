from base64 import b64encode, b64decode

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad

data = b"secret"
key = get_random_bytes(16)
cipher_encrypt = AES.new(key, AES.MODE_CBC)
ct_bytes = cipher_encrypt.encrypt(pad(data, AES.block_size))
iv = b64encode(cipher_encrypt.iv).decode('utf-8')
ct = b64encode(ct_bytes).decode('utf-8')

try:
    iv = b64decode(iv)
    ct = b64decode(ct)
    cipher_decrypt = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher_decrypt.decrypt(ct), AES.block_size)
    print("The message was: ", pt)
except (ValueError, KeyError):
    print("Incorrect decryption")
