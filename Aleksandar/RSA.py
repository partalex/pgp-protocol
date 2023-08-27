import rsa


class RSA:
    @staticmethod
    def encrypt(key, plaintext):
        return rsa.encrypt(plaintext, key)

    @staticmethod
    def decrypt(ciphertext, key):
        return rsa.decrypt(ciphertext, key)

    @staticmethod
    def generateKeyPair(keySize):
        return rsa.newkeys(keySize)

    @staticmethod
    def sign(message, privateKey):
        return rsa.sign(message, privateKey, 'SHA-1')

    @staticmethod
    def verify(message, signature, publicKey):
        return rsa.verify(message, signature, publicKey) == 'SHA-1'


if __name__ == '__main__':
    message = b"Hello Tony, I am Jarvis!"
    print("-" * 50)

    # encrypt with public key
    print("Encrypt and decrypt with RSA.")
    pu, pr = keys = RSA.generateKeyPair(512)
    ciphertext = RSA.encrypt(pu, message)
    print(message)
    print(ciphertext)
    print(RSA.decrypt(ciphertext, pr))

    # sign with private key
    print()
    print("-" * 50)
    print("Sign and verify with RSA.")
    signature = RSA.sign(message, pr)
    print("Signature: ", signature)
    print(RSA.verify(message, signature, pu))
    print("-" * 50)
