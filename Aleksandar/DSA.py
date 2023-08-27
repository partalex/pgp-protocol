import base64

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import DSA as CryptodomeDSA
from Cryptodome.Signature import DSS

from Aleksandar.FileManager import FileManager


class DSA:
    def __init__(self, key, plaintext):
        self.key = key
        self.plaintext = plaintext
        self.signature = self.__sign()

    def __sign(self):
        return DSA.sign(self.plaintext, self.key)

    def __decrypt(self):
        return DSA.verify(self.plaintext, self.signature, self.key)

    def getSignature(self):
        return self.signature

    @staticmethod
    def sign(plaintext, key) -> base64:
        return DSS.new(key, 'fips-186-3').sign(SHA256.new(plaintext))

    @staticmethod
    def signAndExport(plaintext, key) -> str:
        return DSA.sign(plaintext, key).hex()

    @staticmethod
    def verify(plaintext, signature, key) -> bool:
        try:
            DSS.new(key, 'fips-186-3').verify(SHA256.new(plaintext), signature)
            return True
        except ValueError:
            return False

    @staticmethod
    def importAndVerify(plaintext, signature, key) -> bool:
        # hex to bytes
        signature = bytes.fromhex(signature)
        try:
            DSS.new(key, 'fips-186-3').verify(SHA256.new(plaintext), signature)
            return True
        except ValueError:
            return False

    @staticmethod
    def generateKeyPair(keySize):
        key = CryptodomeDSA.generate(keySize)
        PUPem = key.publickey().export_key()
        PRPem = key.export_key()
        return PUPem, PRPem

    @staticmethod
    def importKey(key):
        return CryptodomeDSA.import_key(key.encode('utf-8'))

    @staticmethod
    def exportKey(key) -> str:
        return key.export_key().decode('utf-8')


if __name__ == "__main__":
    key = CryptodomeDSA.generate(1024)
    dsa = DSA(key, b"Hello")
    # print(dsa.sign(b"Hello", key))
    print(dsa.signAndExport(b"Hello", key))
    # print(dsa.getSignature())
    # print(dsa.verify(b"Hello", dsa.signature, dsa.key))

    # key = CryptodomeDSA.generate(1024)
    # keyExported = DSA.exportKey(key)
    # print(keyExported)
    #
    # keyImported = DSA.importKey(keyExported)
    # print(keyImported)

    # # Create a new DSA key
    # key = CryptodomeDSA.generate(2048)
    # f = open("public_key.pem", "wb")
    # f.write(key.publickey().export_key())
    # f.close()
    #
    # # Sign a message
    # message = b"Hello"
    # hash_obj = SHA256.new(message)
    # signer = DSS.new(key, 'fips-186-3')
    # signature = signer.sign(hash_obj)
    #
    # # Load the public key
    # f = open("public_key.pem", "r")
    # hash_obj = SHA256.new(message)
    # pub_key = CryptodomeDSA.import_key(f.read())
    # verifier = DSS.new(pub_key, 'fips-186-3')
    #
    # # Verify the authenticity of the message
    # try:
    #     verifier.verify(hash_obj, signature)
    #     print("The message is authentic.")
    # except ValueError:
    #     print("The message is not authentic.")
