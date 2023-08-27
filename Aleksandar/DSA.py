from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import DSA as Dsa
from Cryptodome.Signature import DSS


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
    def sign(plaintext, key):
        return DSS.new(key, 'fips-186-3').sign(SHA256.new(plaintext))

    @staticmethod
    def verify(plaintext, signature, key):
        try:
            DSS.new(key, 'fips-186-3').verify(SHA256.new(plaintext), signature)
            return True
        except ValueError:
            return False


if __name__ == "__main__":
    # Aleksandar - testiranje klase
    dsa = DSA(Dsa.generate(2048), b"Hello")
    print(dsa.verify(b"Hello", dsa.signature, dsa.key))

    # Marko
    # Create a new DSA key
    key = Dsa.generate(2048)
    f = open("public_key.pem", "wb")
    f.write(key.publickey().export_key())
    f.close()

    # Sign a message
    message = b"Hello"
    hash_obj = SHA256.new(message)
    signer = DSS.new(key, 'fips-186-3')
    signature = signer.sign(hash_obj)

    # Load the public key
    f = open("public_key.pem", "r")
    hash_obj = SHA256.new(message)
    pub_key = Dsa.import_key(f.read())
    verifier = DSS.new(pub_key, 'fips-186-3')

    # Verify the authenticity of the message
    try:
        verifier.verify(hash_obj, signature)
        print("The message is authentic.")
    except ValueError:
        print("The message is not authentic.")