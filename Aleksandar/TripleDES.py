from pyDes import *


class TripleDES:
    def __init__(self, key, plaintext):
        self.key = key
        self.plaintext = plaintext
        self.temp = triple_des(key, CBC, "12345678", pad=None, padmode=PAD_PKCS5)
        self.ciphertext = TripleDES.encrypt(self.temp, self.plaintext)

    @staticmethod
    def encrypt(temp, plaintext):
        return temp.encrypt(plaintext)

    @staticmethod
    def decrypt(temp, ciphertext):
        return temp.decrypt(ciphertext)

    def getCiphertext(self):
        return self.ciphertext

    def verify(self):
        return self.plaintext == TripleDES.decrypt(self.temp, self.ciphertext).decode('utf-8')


if __name__ == '__main__':
    key = "1234567_1234567_1234567_"  # can be 16B or 24B

    tripleDES = TripleDES(key, "Please encrypt my data with 24B key.")
    ciphertext = tripleDES.getCiphertext()
    print(ciphertext)
    print(tripleDES.verify())

    # iv = "12345678"
    # plaintext = "Please encrypt my data with 24B key."
    #
    # temp = triple_des(key, CBC, iv, pad=None, padmode=PAD_PKCS5)
    # cipher = temp.encrypt(plaintext)
    #
    # originalText24B = temp.decrypt(cipher)
    # print("Plaintext:", plaintext)
    # print("Cipher:", cipher)
    # print("Original message:", originalText24B.decode())
    # print("Verify: " + str(originalText24B.decode() == plaintext))
