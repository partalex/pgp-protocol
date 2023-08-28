import rsa

from Aleksandar.DictBytes import DictBytes


class RSA:
    @staticmethod
    def encrypt(plaintext, key) -> bytes:
        return rsa.encrypt(plaintext, key)

    @staticmethod
    def encryptAndExport(plaintext, public_key) -> str:
        return rsa.encrypt(plaintext, public_key).hex()

    @staticmethod
    def decrypt(ciphertext, key) -> bytes:
        return rsa.decrypt(ciphertext, key)

    @staticmethod
    def importAndDecrypt(ciphertext, key) -> bytes:
        # convert from hex to bytes
        ciphertext_bytes = bytes.fromhex(ciphertext)
        return rsa.decrypt(ciphertext_bytes, key)

    @staticmethod
    def decryptToString(ciphertext, key) -> str:
        return rsa.decrypt(ciphertext, key).decode('utf-8')

    @staticmethod
    def generateKeyPair(key_size):
        return rsa.newkeys(key_size)

    @staticmethod
    def sign(message, private_key):
        return rsa.sign(message, private_key, 'SHA-1')

    @staticmethod
    def signAndExport(message, private_key) -> str:
        return rsa.sign(message, private_key, 'SHA-1').hex()

    @staticmethod
    def verify(message, signature, public_key):
        return rsa.verify(message, signature, public_key) == 'SHA-1'

    @staticmethod
    def importAndVerify(message: bytes, signature: str, public_key):
        if RSA.verify(message, bytes.fromhex(signature), public_key):
            return True
        raise Exception("Invalid signature.")

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
    def getKeyId(key) -> int:
        return key.n % 2 ** 32


if __name__ == '__main__':
    message = b"Hello Tony, I am Jarvis!"
    print("-" * 50)

    # encrypt with public key
    print("Encrypt and decrypt with RSA.")
    pu, pr = keys = RSA.generateKeyPair(512)
    # fixme -----------------------

    pu_export = RSA.exportKey(pu)
    pr_export = RSA.exportKey(pr)

    pu_import = RSA.importPublicKey(pu_export)
    pr_import = RSA.importPrivateKey(pr_export)

    # test encryption with public key
    cipher = RSA.encryptAndExport(message, pu_import)
    print(RSA.encryptAndExport(message, pu_import))
    print(RSA.importAndDecrypt(cipher, pr_import))

    exit(0)

    # fixme -----------------------
    ciphertext = RSA.encrypt(message, pu)
    print(message)
    print(ciphertext)
    print(RSA.decrypt(ciphertext, pr))

    # sign with private key
    print()
    print("-" * 50)
    print("Sign and verify with RSA.")
    signature = RSA.hash(message, pr)
    print(signature)
    # test type of signature
    print(signature.hex())
    print("Signature: ", signature)
    print(RSA.importAndDecrypt(message, signature, pu))
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
