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
    PU, PR = RSA.generateKeyPair(512)

    print("Private key: ", PR)
    print("Public key: ", PU)
    rsaObject = RSA(PU, message)
    ciphertext = rsaObject.getCiphertext()
    print("Ciphertext: ", ciphertext)
    print("Verify: ", rsaObject.verify(PR))

    # encrypt with public key
    pr, pu = rsa.newkeys(512)
    ciphertext = rsa.encrypt(message, pr)
    verify = rsa.decrypt(ciphertext, pu)
    print("Verify: ", verify == message)

    # encrypt with private key
    ciphertext = rsa.encrypt(message, pu)
    verify = rsa.decrypt(ciphertext, pr)
    print("Verify: ", verify == message)
