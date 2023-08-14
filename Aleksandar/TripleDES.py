from base64 import b64encode, b64decode

from pyDes import triple_des, CBC, PAD_PKCS5


class TripleDES:
    def __init__(self, key):
        self.key = key

    defaultKey16B = "1234567_1234567_"
    defaultKey24B = "1234567_1234567_1234567_"
    initVectorCBC = "12345678"

    # generete encrypt24B
    def encrypt24B(self, message):
        cipher_encrypt = triple_des(self.defaultKey24B, CBC, self.initVectorCBC, pad=None, padmode=PAD_PKCS5)
        ct_bytes = cipher_encrypt.encrypt(message)
        iv = b64encode(cipher_encrypt.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        return iv, ct

    def decrypt24B(self, iv, ct):
        iv = b64decode(iv)
        ct = b64decode(ct)
        cipher_decrypt = triple_des(self.defaultKey24B, CBC, iv, pad=None, padmode=PAD_PKCS5)
        pt = cipher_decrypt.decrypt(ct)
        return pt