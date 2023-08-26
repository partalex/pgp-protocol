import rsa

from Aleksandar.FileJSON import FileJSON
from Aleksandar.Timestamp import Timestamp


class Keyring:
    def __init__(self, filename="keyring"):
        self.filename = filename
        self.__initialise()

    def __initialise(self):
        self.ring = FileJSON.readFromFile(self.filename)
        for key in self.ring:
            with open("./RSAKeys/" + key["publicKey"], 'r') as the_file:
                publicKey = rsa.PublicKey.load_pkcs1(the_file.read().encode('utf8'))
                key["publicKey"] = publicKey
                key["timestamp"] = Timestamp.generateString()
                key["keyId"] = key["publicKey"].n % 2 ** 32  # TODO - Check if this is correct.

    def getPublicKeyByKeyId(self, keyId):
        for key in self.ring:
            if key["keyId"] == keyId:
                return key["publicKey"]
        raise Exception("Key not found.")

    def getPublicKeyByUserId(self, userId, password):
        for key in self.ring:
            if key["userId"] == userId and key["password"] == password:
                return key["publicKey"]
        raise Exception("Key not found.")


if __name__ == "__main__":

    keyring = Keyring()
    print("--------------------------------------------------")
    for key in keyring.ring:
        print("Public key: ", key["publicKey"])
        print("Timestamp: ", key["timestamp"])
        print("Key ID: ", key["keyId"])
        print("User ID: ", key["userId"])
        print("Password: ", key["password"])
        print("--------------------------------------------------")
