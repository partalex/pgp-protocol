import rsa
from Cryptodome.PublicKey import DSA as CryptodomeDSA

from Aleksandar.DSA import DSA
from RSA import RSA
from Timestamp import Timestamp


class KeyRing:
    def __init__(self):
        self.ring = []

    def generateRSAKeys(self, keySize, userId, password):
        PUPem, PRPem = RSA.generateKeyPair(keySize)
        self.ring.append({
            "publicKey": PUPem,
            "privateKey": PRPem,
            "timestamp": Timestamp.generateString(),
            "keyId": PUPem.n % 2 ** 32,
            "userId": userId,
            "password": password
        })

    def generateDSAKeys(self, keySize, userId, password):
        PUPem, PRPem = DSA.generateKeyPair(keySize)
        self.ring.append({
            "publicKey": PUPem.decode('utf-8'),
            "privateKey": PRPem.decode('utf-8'),
            "timestamp": Timestamp.generateString(),
            "keyId": DSA.importKey(PUPem).y % 2 ** 32,
            "userId": userId,
            "password": password
        })

    def getPublicKeyByKeyId(self, keyId):
        for keyRing in self.ring:
            if keyRing["keyId"] == keyId:
                return keyRing["publicKey"]
        raise Exception("Key not found.")

    def getPublicKeyByUserId(self, userId, password):
        for keyRing in self.ring:
            if keyRing["userId"] == userId and keyRing["password"] == password:
                return keyRing["publicKey"]
        raise Exception("Key not found.")

    def print(self):
        print("--------------------------------------------------")
        for key in self.ring:
            print("Public key: ", key["publicKey"])
            # print("Private key: ", key["privateKey"])
            print("Timestamp: ", key["timestamp"])
            print("Key ID: ", key["keyId"])
            print("User ID: ", key["userId"])
            print("Password: ", key["password"])
            print("--------------------------------------------------")


if __name__ == "__main__":
    keyRing = KeyRing()
    keyRing.print()
