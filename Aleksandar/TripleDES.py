from pyDes import *
from Cryptodome.Random import get_random_bytes


class TripleDES:
    def __init__(self, key, plaintext, IV="00000000"):
        self.key = key
        self.plaintext = plaintext
        self.ciphertext = TripleDES.encrypt(plaintext, key, IV)

    @staticmethod
    def encrypt(plaintext, key, IV="00000000"):
        return triple_des(key, CBC, IV, pad=None, padmode=PAD_PKCS5).encrypt(plaintext)

    @staticmethod
    def generateKey(key, IV="00000000"):
        return triple_des(key, CBC, IV, pad=None, padmode=PAD_PKCS5)

    @staticmethod
    def decrypt(ciphertext, key, IV="00000000"):
        return triple_des(key, CBC, IV, pad=None, padmode=PAD_PKCS5).decrypt(ciphertext)

    def getCiphertext(self):
        return self.ciphertext

    def verify(self):
        return self.plaintext == TripleDES.decrypt(self.temp, self.ciphertext).decode('utf-8')

    @staticmethod
    def importKey(key) -> str:
        return key

    @staticmethod
    def exportKey(key) -> str:
        return key


if __name__ == '__main__':
    key = "1234567_1234567_1234567_"  # can be 16B or 24B
    plaintext = "Please encrypt my data with 24B key."

    ciphertext_1 = TripleDES.encrypt(plaintext, key)
    ciphertext_2 = TripleDES.encrypt(plaintext, key)

    originalText24B_1 = TripleDES.decrypt(ciphertext_1, key)
    originalText24B_2 = TripleDES.decrypt(ciphertext_1, key)

    print("Original message 1:", originalText24B_1.decode())
    print("Original message 2:", originalText24B_2.decode())

    # iv = "12345678"
    #
    # temp = triple_des(key, CBC, iv, pad=None, padmode=PAD_PKCS5)
    # cipher = temp.encrypt(plaintext)
    #
    # originalText24B = temp.decrypt(cipher)
    # print("Plaintext:", plaintext)
    # print("Cipher:", cipher)
    # print("Original message:", originalText24B.decode())
    # print("Verify: " + str(originalText24B.decode() == plaintext))
