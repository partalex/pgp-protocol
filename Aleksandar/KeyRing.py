from Aleksandar.DSA import DSA
from RSA import RSA
from Timestamp import Timestamp


class KeyRing:
    def __init__(self):
        self.ring = []

    def generateRSAKeys(self, keySize, userId, password):
        PUPem, PRPem = RSA.generateKeyPair(keySize)
        self.ring.append({
            "Public key": PUPem,
            "Private key": PRPem,
            "Timestamp": Timestamp.generateString(),
            "Key Id": PUPem.n % 2 ** 32,
            "User Id": userId,
            "Password": password,
            "Type": "RSA"
        })

    def generateDSAKeys(self, keySize, userId, password):
        PUPem, PRPem = DSA.generateKeyPair(keySize)
        self.ring.append({
            "publicKey": PUPem.decode('utf-8'),
            "privateKey": PRPem.decode('utf-8'),
            "timestamp": Timestamp.generateString(),
            "keyId": DSA.importKey(PUPem).y % 2 ** 32,
            "userId": userId,
            "password": password,
            "type": "DSA"
        })

    def getPrivateKeyByKeyId(self, keyId):
        for keyRing in self.ring:
            if keyRing["keyId"] == keyId:
                return keyRing["privateKey"]
        raise Exception("Key not found.")

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
            ## print all fields
            print("Public key: ", key["Public key"])
            print("Private key: ", key["Private key"])
            print("Timestamp: ", key["Timestamp"])
            print("Key Id: ", key["Key Id"])
            print("User Id: ", key["User Id"])
            print("Password: ", key["Password"])
            print("Type: ", key["Type"])
            print("--------------------------------------------------")


if __name__ == "__main__":
    keyRing = KeyRing()
    keyRing.generateRSAKeys(1024, "Aleksandar", "123")
    keyRing.print()
