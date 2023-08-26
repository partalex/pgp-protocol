from Cryptodome.PublicKey import DSA
from Cryptodome.Hash import SHA1
from Cryptodome.Signature import DSS
import random


class ElGamalPublicKey:
    def __init__(self, q, h):
        self.q = q
        self.h = h


class ElGamalPrivateKey:
    def __init__(self, x, p, q):
        self.x = x
        self.p = p
        self.q = q


def power(a, b, c):
    x = 1
    y = a
    while b > 0:
        if b % 2 != 0:
            x = (x * y) % c;
        y = (y * y) % c
        b = int(b / 2)
    return x % c


def gcd(a, b):
    if a < b:
        return gcd(b, a)
    elif a % b == 0:
        return b
    else:
        return gcd(b, a % b)


def gen_key(keySize):
    dsa_key = DSA.generate(keySize)
    privateKey = ElGamalPrivateKey(dsa_key.x, dsa_key.p, dsa_key.q)
    h = power(dsa_key.g, dsa_key.x, dsa_key.q)
    publicKey = ElGamalPublicKey(dsa_key.q, h)
    return privateKey, publicKey


def random_num(q):
    num = random.randint(pow(10, 20), q)
    while gcd(q, num) != 1:
        num = random.randint(pow(10, 20), q)

    return num


def encrypt(msg, publicKey):
    en_msg = []

    s = power(publicKey.h, random_num(publicKey.q), publicKey.q)

    for i in range(0, len(msg)):
        en_msg.append(msg[i])
    for i in range(0, len(en_msg)):
        en_msg[i] = s * ord(en_msg[i])
    return en_msg


def decrypt(en_msg, privateKey):
    dr_msg = []
    h = power(privateKey.p, privateKey.x, privateKey.q)
    for i in range(0, len(en_msg)):
        dr_msg.append(chr(int(en_msg[i] / h)))

    return dr_msg


if __name__ == '__main__':
    privateKey, publicKey = gen_key(2048)
    msg = 'encryption'
    msg_stream = bytes(msg, "utf-8")
    print("Original Message :", msg)
    en_msg = encrypt(msg, publicKey)
    dr_msg = decrypt(en_msg, privateKey)
    msg_stream = bytes(''.join(dr_msg), "utf-8")
    dmsg = ''.join(dr_msg)
    print("Decrypted Message :", dmsg)
