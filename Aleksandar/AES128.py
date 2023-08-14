from base64 import b64encode, b64decode

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad


class AES128:
    def __init__(self, key):
        self.key = key

    def encrypt(self, message):
        cipher_encrypt = AES.new(self.key, AES.MODE_CBC)
        ct_bytes = cipher_encrypt.encrypt(pad(message, AES.block_size))
        iv = b64encode(cipher_encrypt.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        return iv, ct

    def decrypt(self, iv, ct):
        iv = b64decode(iv)
        ct = b64decode(ct)
        cipher_decrypt = AES.new(self.key, AES.MODE_CBC, iv)
        pt = unpad(cipher_decrypt.decrypt(ct), AES.block_size)
        return pt
