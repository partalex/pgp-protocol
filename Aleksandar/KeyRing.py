from Aleksandar.DSA import DSA
from Aleksandar.ElGamal import ElGamal
from RSA import RSA
from Timestamp import Timestamp


class KeyRing:
    def __init__(self):
        self.ring = []

    def generateRSAKeys(self, key_size, user_id, password):
        publicKey, privateKey = RSA.generateKeyPair(key_size)
        self.ring.append({
            "Public key": RSA.exportKey(publicKey),
            "Private key": RSA.exportKey(privateKey),
            "Timestamp": Timestamp.generateString(),
            "Key Id": RSA.getKeyId(publicKey),
            "User Id": user_id,
            "Password": password,
            "Type": "RSA"
        })

    def generateElGamalKeys(self, key_size, user_id, password):
        keys = ElGamal.generateKeyPair(key_size)
        public_key = keys["Public key"]
        private_key = keys["Private key"]
        self.ring.append({
            "Public key": public_key,
            "Private key": private_key,
            "Timestamp": Timestamp.generateString(),
            "Key Id": ElGamal.getKeyId(public_key),
            "User Id": user_id,
            "Password": password,
            "Type": "ElGamal"
        })

    def generateDSAKeys(self, key_size, user_id, password):
        keys = DSA.generateKeyPair(key_size)
        self.ring.append({
            "Public key": DSA.exportPublicKey(keys),
            "Private key": DSA.exportPrivateKey(keys),
            "Timestamp": Timestamp.generateString(),
            "Key Id": DSA.getKeyId(keys),
            "User Id": user_id,
            "Password": password,
            "Type": "ElGamal"
        })

    def getPrivateKeyByKeyId(self, key_id):
        for key_ring in self.ring:
            if key_ring["Key Id"] == key_id:
                return key_ring["Private key"]
        raise Exception("Key not found.")

    def getPublicKeyByKeyId(self, key_id):
        for key_ring in self.ring:
            if key_ring["Key Id"] == key_id:
                return key_ring["Public key"]
        raise Exception("Key not found.")

    def getPublicKeyByUserId(self, userId, password):
        for key_ring in self.ring:
            if key_ring["User Id"] == userId and key_ring["Password"] == password:
                return key_ring["publicKey"]
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
