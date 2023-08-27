from Cryptodome.PublicKey import DSA
import random


class ElGamal:
    def __init__(self, plaintext, keySize):
        self.plaintext = plaintext
        self.keySet = self.generateKey(keySize)
        self.p = self.keySet[0]
        self.g = self.keySet[1]
        self.x = random.randint(1, self.p - 1)  # Private key.
        self.y = pow(self.g, self.x, self.p)  # Public key.
        self.c1, self.c2 = self.encrypt(self.plaintext, self.y, self.g, self.p)

    @staticmethod
    def generateKey(keySize):
        dsaKeys = DSA.generate(keySize)
        p = dsaKeys.p
        g = dsaKeys.g
        x = random.randint(1, p - 1)  # Privatni ključ
        y = pow(g, x, p)  # Javni ključ
        return p, g, x, y

    def getCiphertext(self):
        return self.c1, self.c2

    @staticmethod
    def encrypt(message, y, g, p):
        k = random.randint(1, p - 1)
        c1 = pow(g, k, p)
        c2 = (message * pow(y, k, p)) % p
        return c1, c2

    @staticmethod
    def decrypt(c1, c2, x, p):
        s = pow(c1, x, p)
        message = (c2 * pow(s, -1, p)) % p
        return message

    @staticmethod
    def verifyMessage(plaintext, c1, c2, x, p):
        return plaintext == ElGamal.decrypt(c1, c2, x, p)

    def verify(self):
        return self.verifyMessage(self.plaintext, self.c1, self.c2, self.x, self.p)


if __name__ == '__main__':
    print("-------------------ELGAMAL-------------------")
    message = 1234
    elgamal = ElGamal(message, 1024)
    print("Originalna poruka:", message)
    print("Dekriptovana poruka:", elgamal.verify())

    print("-------------------ELGAMAL-------------------")
    message = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua"
    messageToInt = int.from_bytes(message.encode(), 'big')
    elgamal = ElGamal(messageToInt, 1024)

    print("Originalna poruka:", message)
    print("Dekriptovana poruka:", elgamal.verify())
