from base64 import b64encode, b64decode

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad


class TripleDES:
    @staticmethod
    def encrypt(message):
        data = message.encode('utf-8')
        key = get_random_bytes(16)
        cipher_encrypt = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher_encrypt.encrypt(pad(data, AES.block_size))
        iv = b64encode(cipher_encrypt.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        iv = cipher_encrypt.iv
        ct = ct_bytes
        return iv, ct, key

    @staticmethod
    def dencrypt(iv, ct, key):
        try:
            cipher_decrypt = AES.new(key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher_decrypt.decrypt(ct), AES.block_size)
            print("The message was: ", plaintext)
        except (ValueError, KeyError):
            print("Incorrect decryption")


if __name__ == '__main__':
    message = "The answer is no!"
    cipher = TripleDES.encrypt(message)
    TripleDES.dencrypt(cipher[0], cipher[1], cipher[2])
