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
    def encryptAndExport(plaintext, key, IV="00000000") -> str:
        return triple_des(key, CBC, IV, pad=None, padmode=PAD_PKCS5).encrypt(plaintext).hex()

    @staticmethod
    def importAndDecrypt(plaintext, key, IV="00000000"):
        return triple_des(key, CBC, IV, pad=None, padmode=PAD_PKCS5).decrypt(bytes.fromhex(plaintext))

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
    plaintext = b"Please encrypt my data with 24B key."

    ciphertext = TripleDES.encryptAndExport(plaintext, key)
    print("Ciphertext:", ciphertext)

    originalText = TripleDES.importAndDecrypt(ciphertext, key)
    print("Original message:", originalText)

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
