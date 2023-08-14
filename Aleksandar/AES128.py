from base64 import b64encode, b64decode

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad


def AES128_encrypt(message, key):
    cipher_encrypt = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher_encrypt.encrypt(pad(message, AES.block_size))
    iv = b64encode(cipher_encrypt.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    return iv, ct


def AES128_decrypt(key, iv, ct):
    iv = b64decode(iv)
    ct = b64decode(ct)
    cipher_decrypt = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher_decrypt.decrypt(ct), AES.block_size)
    return pt
