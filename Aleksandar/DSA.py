import base64

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import DSA as CryptodomeDSA
from Cryptodome.Signature import DSS


class DSA:
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
        return CryptodomeDSA.generate(keySize)

    @staticmethod
    def exportPrivateKey(key) -> str:
        return key.export_key().decode('utf-8')

    @staticmethod
    def exportPublicKey(key) -> str:
        return key.export_key().decode('utf-8')

    @staticmethod
    def importKey(key):
        return CryptodomeDSA.import_key(key.encode('utf-8'))

    @staticmethod
    def getKeyId(key) -> int:
        return key.y % 2 ** 32


if __name__ == "__main__":
    key = DSA.generateKeyPair(1024)

    print(DSA.exportPrivateKey(key))
    print(DSA.exportPublicKey(key))

    pr = DSA.importKey(DSA.exportPrivateKey(key))
    pu = DSA.importKey(DSA.exportPublicKey(key))

    print(DSA.getKeyId(key))

    # test encrypt
    plaintext = b"Hello"
    signature = DSA.signAndExport(plaintext, pr)
    print(signature)
    print(DSA.importAndVerify(plaintext, signature, pu))

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
