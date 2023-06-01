from Cryptodome.PublicKey import DSA
from Cryptodome.Hash import SHA1
from Cryptodome.Signature import DSS
import random


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


def gen_key(q):
    key = random.randint(pow(10, 20), q)
    while gcd(q, key) != 1:
        key = random.randint(pow(10, 20), q)

    return key


def encrypt(msg, q, h, g):
    en_msg = []

    k = gen_key(q)  # Private key for sender
    s = power(h, k, q)
    p = power(g, k, q)

    for i in range(0, len(msg)):
        en_msg.append(msg[i])
    for i in range(0, len(en_msg)):
        en_msg[i] = s * ord(en_msg[i])

    return en_msg, p


def decrypt(en_msg, p, key, q):
    dr_msg = []
    h = power(p, key, q)
    for i in range(0, len(en_msg)):
        dr_msg.append(chr(int(en_msg[i] / h)))

    return dr_msg


if __name__ == '__main__':
    dsa_key = DSA.generate(2048)
    msg = 'encryption'
    msg_stream = bytes(msg, "utf-8")
    hash_obj = SHA1.new(msg_stream)
    signer = DSS.new(dsa_key, 'fips-186-3')
    signature = signer.sign(hash_obj)
    print("Original Message :", msg)

    key = gen_key(dsa_key.q)  # Private key for receiver
    h = power(dsa_key.g, key, dsa_key.q)

    en_msg, p = encrypt(msg, dsa_key.q, h, dsa_key.g)
    dr_msg = decrypt(en_msg, p, key, dsa_key.q)
    msg_stream = bytes(''.join(dr_msg), "utf-8")
    hash_obj = SHA1.new(msg_stream)
    verifier = DSS.new(dsa_key, 'fips-186-3')
    try:
        verifier.verify(hash_obj, signature)
        print("The message is authentic.")
    except ValueError:
        print("The message is not authentic.")
    dmsg = ''.join(dr_msg)
    print("Decrypted Message :", dmsg)
