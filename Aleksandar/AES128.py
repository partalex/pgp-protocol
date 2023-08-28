import os
from base64 import b64encode, b64decode

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad


class AES128:
    def __init__(self, key, plaintext):
        self.key = key
        self.plaintext = plaintext
        self.iv, self.ciphertext = self.__encrypt()

    def __encrypt(self):
        return AES128.encrypt(self.plaintext, self.key)

    def __decrypt(self):
        return AES128.decrypt(self.ciphertext, self.key, self.iv)

    def getCiphertext(self):
        return self.ciphertext

    @staticmethod
    def encrypt(plaintext, key):
        cipher_encrypt = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher_encrypt.encrypt(pad(plaintext, AES.block_size))
        iv = b64encode(cipher_encrypt.iv)  # radi i bez decode
        # iv = b64encode(cipher_encrypt.iv).decode('utf-8')
        ct = b64encode(ct_bytes)  # radi i bez decode
        # ct = b64encode(ct_bytes).decode('utf-8')
        return {"iv": iv, "ciphertext": ct}

    @staticmethod
    def encryptAndExport(plaintext, key):
        data = AES128.encrypt(plaintext, key)
        iv = data['iv'].decode('utf-8')
        ciphertext = data['ciphertext'].decode('utf-8')
        return {"iv": iv, "ciphertext": ciphertext}

    @staticmethod
    def decrypt(ciphertext, key, iv):
        iv = b64decode(iv)
        ciphertext = b64decode(ciphertext)
        cipher_decrypt = AES.new(key, AES.MODE_CBC, IV=iv)
        plaintext = unpad(cipher_decrypt.decrypt(ciphertext), AES.block_size)
        return plaintext

    @staticmethod
    def importAndDecrypt(ciphertext, key):
        iv = ciphertext['iv']
        ciphertext = ciphertext['ciphertext']
        iv = iv.encode('utf-8')
        ciphertext = ciphertext.encode('utf-8')
        return AES128.decrypt(ciphertext, key, iv)

    @staticmethod
    def import_key(key :str)->bytes:
        return b64decode(key)

    @staticmethod
    def export_key(key :bytes)->str:
        return b64encode(key).decode('utf-8')


if __name__ == "__main__":
    key = get_random_bytes(16)
    message = b'Hello World'
    print("Plaintext: \n\t" + message.decode())

    ciphertext = AES128.encryptAndExport(message, key)

    print("Encryption parameters:")
    print("\tct = " + str(ciphertext))

    print("Original message: \n\t" + AES128.importAndDecrypt(ciphertext, key).decode('utf-8'))

    # data = AES128.encrypt(message, key)
    # print("Encryption parameters:")
    # print("\tiv = " + data['iv'].decode('utf-8'))
    # print("\tct = " + data['ciphertext'].decode('utf-8'))
    #
    # ciphertext = data['ciphertext']
    # iv = data['iv']
    #
    # print("Original message: \n\t" + AES128.decrypt(ciphertext, key, iv).decode('utf-8'))
