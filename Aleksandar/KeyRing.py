from Aleksandar.DSA import DSA
from Aleksandar.ElGamal import ElGamal
from RSA import RSA
from Timestamp import Timestamp


class KeyRing:
    def __init__(self):
        self.ring = []

    def generateRSAKeys(self, keySize, userId, password):
        publicKey, privateKey = RSA.generateKeyPair(keySize)
        self.ring.append({
            "Public key": RSA.exportKey(publicKey),
            "Private key": RSA.exportKey(privateKey),
            "Timestamp": Timestamp.generateString(),
            "Key Id": RSA.getKeyId(publicKey),
            "User Id": userId,
            "Password": password,
            "Type": "RSA"
        })

    def generateElGamalKeys(self, keySize, userId, password):
        keys = ElGamal.generateKeyPair(keySize)
        publicKey = keys["Public key"]
        privateKey = keys["Private key"]
        self.ring.append({
            "Public key": publicKey,
            "Private key": privateKey,
            "Timestamp": Timestamp.generateString(),
            "Key Id": ElGamal.getKeyId(publicKey),
            "User Id": userId,
            "Password": password,
            "Type": "ElGamal"
        })

    def generateDSAKeys(self, keySize, userId, password):
        keys = DSA.generateKeyPair(keySize)
        self.ring.append({
            "Public key": DSA.exportPublicKey(keys),
            "Private key": DSA.exportPrivateKey(keys),
            "Timestamp": Timestamp.generateString(),
            "Key Id": DSA.getKeyId(keys),
            "User Id": userId,
            "Password": password,
            "Type": "ElGamal"
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
    keyRing.generateElGamalKeys(1024, "Aleksandar", "123")
    keyRing.print()
