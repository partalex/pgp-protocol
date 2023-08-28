import rsa

from Aleksandar.DictBytes import DictBytes


class RSA:
    @staticmethod
    def encrypt(plaintext, key) -> bytes:
        return rsa.encrypt(plaintext, key)

    @staticmethod
    def encryptAndExport(plaintext, key) -> str:
        return rsa.encrypt(plaintext, key).decode('utf-8')

    @staticmethod
    def decrypt(ciphertext, key) -> bytes:
        return rsa.decrypt(ciphertext, key)

    @staticmethod
    def importAndDecrypt(ciphertext, key) -> bytes:
        return rsa.decrypt(ciphertext.encode('utf-8'), key)

    @staticmethod
    def decryptToString(ciphertext, key) -> str:
        return rsa.decrypt(ciphertext, key).decode('utf-8')

    @staticmethod
    def generateKeyPair(keySize):
        return rsa.newkeys(keySize)

    @staticmethod
    def sign(message, privateKey):
        return rsa.sign(message, privateKey, 'SHA-1')

    @staticmethod
    def signAndExport(message, privateKey) -> str:
        return rsa.sign(message, privateKey, 'SHA-1').hex()

    @staticmethod
    def verify(message, signature, publicKey):
        return rsa.verify(message, signature, publicKey) == 'SHA-1'

    @staticmethod
    def importAndVerify(message, signature, publicKey):
        return rsa.verify(message, bytes.fromhex(signature), publicKey) == 'SHA-1'

    @staticmethod
    def exportKey(key) -> str:
        return key.save_pkcs1(format='PEM').decode('utf-8')

    @staticmethod
    def importPublicKey(key):
        key = key.encode('utf-8')
        return rsa.PublicKey.load_pkcs1(key, format='PEM')

    @staticmethod
    def importPrivateKey(key):
        key = key.encode('utf-8')
        return rsa.PrivateKey.load_pkcs1(key, format='PEM')

    @staticmethod
    def getKeyId(key)->int:
        return key.n % 2 ** 32


if __name__ == '__main__':
    message = b"Hello Tony, I am Jarvis!"
    print("-" * 50)

    # encrypt with public key
    print("Encrypt and decrypt with RSA.")
    pu, pr = keys = RSA.generateKeyPair(512)
    ciphertext = RSA.encrypt(message, pu)
    print(message)
    print(ciphertext)
    print(RSA.decrypt(ciphertext, pr))

    # sign with private key
    print()
    print("-" * 50)
    print("Sign and verify with RSA.")
    signature = RSA.sign(message, pr)
    print(signature)
    # test type of signature
    print(signature.hex())
    print("Signature: ", signature)
    print(RSA.verify(message, signature, pu))
    print("-" * 50)

    pu, pr = RSA.generateKeyPair(512)

    test = {
        "Public Key": RSA.exportKey(pu),
        "Private Key": RSA.exportKey(pr)
    }
    print("-" * 50)

    testBytes = DictBytes.dictToBytes(test)
    print(testBytes)
    testDict = DictBytes.bytesToDict(testBytes)
    print(testDict)

    print("-" * 50)

    print(RSA.importPublicKey(testDict["Public Key"]))
    print(RSA.importPrivateKey(testDict["Private Key"]))
