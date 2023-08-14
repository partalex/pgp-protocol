from Cryptodome.Random import get_random_bytes
from pyDes import des, CBC, PAD_PKCS5, triple_des


class TripleDES:
    @staticmethod
    def encrypt(plaintext, key=get_random_bytes(24), iv='\0\0\0\0\0\0\0\0'):
        temp = triple_des(key, CBC, iv, pad=None, padmode=PAD_PKCS5)
        cipher = temp.encrypt(plaintext)
        return cipher

    @staticmethod
    def decrypt(key, cipher, iv='\0\0\0\0\0\0\0\0'):
        temp = triple_des(key, CBC, iv, pad=None, padmode=PAD_PKCS5)
        plaintext = temp.decrypt(cipher)
        return plaintext


if __name__ == '__main__':
    plaintext = b"Please encrypt my data with 24B key. If you want to use 16B key, use 3DES.py."
    print("Plaintext: %r" % plaintext)

    key = get_random_bytes(24)
    iv = '\0\0\0\0\0\0\0\0'
    cipher = TripleDES.encrypt(plaintext, key, iv)
    print("Encrypted: %r" % cipher)

    originalText = TripleDES.decrypt(key, cipher, iv)
    print("Decrypted: %r" % originalText)
