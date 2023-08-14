from base64 import b64encode, b64decode

from pyDes import triple_des, CBC, PAD_PKCS5


class TripleDES:
    @staticmethod
    def encrypt24B(message, key24B='1234567_1234567_1234567_', initVectorCBC='12345678'):
        cipher_encrypt = triple_des(key24B, CBC, initVectorCBC, pad=None, padmode=PAD_PKCS5)
        ct_bytes = cipher_encrypt.encrypt(message)
        iv = b64encode(cipher_encrypt.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        return iv, ct

    @staticmethod
    def decrypt24B(key24B, iv, ct):
        iv = b64decode(iv)
        ct = b64decode(ct)
        cipher_decrypt = triple_des(key24B, CBC, iv, pad=None, padmode=PAD_PKCS5)
        pt = cipher_decrypt.decrypt(ct)
        return pt
