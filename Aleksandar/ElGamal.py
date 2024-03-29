from Cryptodome.PublicKey import DSA
import random


class ElGamal:
    def __init__(self, plaintext, keySize):
        pass
        # self.plaintext = plaintext
        # self.keySet = self.generateKey(keySize)
        # self.p = self.keySet['p']
        # self.g = self.keySet['g']
        # self.privateKey = random.randint(1, self.p - 1)  # Private key. x
        # self.publicKey = pow(self.g, self.privateKey, self.p)  # Public key. y
        # self.c1, self.c2 = ElGamal.__encrypt(self.plaintext, self.publicKey, self.g, self.p)

    @staticmethod
    def generateKeyPair(keySize) -> dict:
        dsaKeys = DSA.generate(keySize)
        p = dsaKeys.p
        g = dsaKeys.g
        x = random.randint(1, p - 1)  # Private key = x.
        y = pow(g, x, p)  # Public key = y.
        return {"Public key": {"Public key": y, "g": g, "p": p}, "Private key": {"Private key": x, "p": p}}

    @staticmethod
    def getKeyId(key: dict) -> int:
        return key['Public key'] % 2 ** 32

    @staticmethod
    def generateKey(keySize) -> dict:
        dsaKeys = DSA.generate(keySize)
        p = dsaKeys.p
        g = dsaKeys.g
        x = random.randint(1, p - 1)  # Private key = x.
        y = pow(g, x, p)  # Public key = y.
        return {"p": p, "g": g, "Private key": x, "Public key": y}

    @staticmethod
    def __encrypt(plaintext, publicKey, g, p) -> dict:
        k = random.randint(1, p - 1)
        c1 = pow(g, k, p)
        c2 = (plaintext * pow(publicKey, k, p)) % p
        return {"c1": c1, "c2": c2}

    @staticmethod
    def encryptAndExport(plaintext, key) -> dict:
        plaintext = int.from_bytes(plaintext, 'big')
        return ElGamal.__encrypt(plaintext, key['Public key'], key['g'], key['p'])

    @staticmethod
    def __decrypt(c1, c2, privateKey, p) -> int:
        s = pow(c1, privateKey, p)
        message = (c2 * pow(s, -1, p)) % p
        return message

    @staticmethod
    def __verify(plaintext, c1, c2, privateKey, p) -> bool:
        return plaintext == ElGamal.__decrypt(c1, c2, privateKey, p)

    @staticmethod
    def importAndVerify(plaintext, ciphertext, privateKey: dict) -> bool:
        c1 = ciphertext['c1']
        c2 = ciphertext['c2']
        plaintextInt = int.from_bytes(plaintext, 'big')
        return ElGamal.__verify(plaintextInt, c1, c2, privateKey['Private key'], privateKey['p'])

    @staticmethod
    def importAndDecrypt(ciphertext, privateKey: dict) -> bytes:
        c1 = ciphertext['c1']
        c2 = ciphertext['c2']
        int_message = ElGamal.__decrypt(c1, c2, privateKey['Private key'], privateKey['p'])
        to_bytes = int_message.to_bytes((int_message.bit_length() + 7) // 8, 'big')
        return to_bytes

    @staticmethod
    def getSignKey(key) -> dict:
        return {'p': key['p'], 'g': key['g'], 'Public key': key['Public key']}

    @staticmethod
    def getVerifyKey(key) -> dict:
        return {'p': key['p'], 'Private key': key['Private key']}


if __name__ == '__main__':
    print("-------------------ELGAMAL-------------------")
    plaintext = (b"lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et"
                 b" dolore magna aliqua")

    keys = ElGamal.generateKeyPair(1024)

    ciphertext = ElGamal.encryptAndExport(plaintext, keys['Public key'])

    privateKey = keys['Private key']

    flag = ElGamal.importAndVerify(plaintext, ciphertext, privateKey)

    originalTest = ElGamal.importAndDecrypt(ciphertext, privateKey)

    print("Originalna poruka:", plaintext)
    print("Kriptovana poruka", ciphertext)
    print("Radi: ", flag)
    print("Dekriptovana poruka:", originalTest)
