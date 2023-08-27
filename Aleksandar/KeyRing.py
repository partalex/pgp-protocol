import rsa

from Aleksandar.FileJSON import FileJSON
from Aleksandar.Timestamp import Timestamp


class KeyRing:
    def __init__(self, filename="./resources/keyring"):
        self.filename = filename
        self.__initialise()

    def __initialise(self):
        self.ring = FileJSON.readFromFile(self.filename)
        for keyRing in self.ring:
            with open("./resources/" + keyRing["publicKey"], 'r') as the_file:
                publicKey = rsa.PublicKey.load_pkcs1(the_file.read().encode('utf8'))
                keyRing["publicKey"] = publicKey
                keyRing["timestamp"] = Timestamp.generateString()
                keyRing["keyId"] = keyRing["publicKey"].n % 2 ** 32  # TODO - Check if this is correct.

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
            print("Timestamp: ", key["timestamp"])
            print("Key ID: ", key["keyId"])
            print("User ID: ", key["userId"])
            print("Password: ", key["password"])
            print("--------------------------------------------------")


if __name__ == "__main__":
    keyring = KeyRing()
    keyring.print()
