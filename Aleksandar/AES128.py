from base64 import b64encode, b64decode

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad


class AES128:
    @staticmethod
    def encrypt(plaintext, key):
        cipher_encrypt = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher_encrypt.encrypt(pad(plaintext, AES.block_size))
        iv = b64encode(cipher_encrypt.iv)  # radi i bez decode
        # iv = b64encode(cipher_encrypt.iv).decode('utf-8')
        ct = b64encode(ct_bytes)  # radi i bez decode
        # ct = b64encode(ct_bytes).decode('utf-8')
        return iv, ct

    @staticmethod
    def decrypt(key, iv, ciphertext):
        iv = b64decode(iv)
        ciphertext = b64decode(ciphertext)
        cipher_decrypt = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher_decrypt.decrypt(ciphertext), AES.block_size)
        return plaintext


if __name__ == "__main__":
    key = get_random_bytes(16)
    message = b'Hello World'
    print("Plaintext: \n\t" + message.decode())

    data = AES128.encrypt(message, key)
    print("Encryption parameters:")
    print("\tiv = " + data[0].decode('utf-8'))
    print("\tct = " + data[1].decode('utf-8'))

    print("Original message: \n\t" + AES128.decrypt(key, data[0], data[1]).decode('utf-8'))
