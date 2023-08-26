from base64 import b64encode, b64decode
import rsa
from Crypto.Hash import SHA

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5


def importKey(externKey):
    return RSA.importKey(externKey)


def getpublickey(priv_key):
    return priv_key.publickey()


def encrypt(message, pub_key):
    # RSA encryption protocol according to PKCS#1 OAEP
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(message)


def decrypt(ciphertext, priv_key):
    # RSA encryption protocol according to PKCS#1 OAEP
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(ciphertext)


def sign(message, privateKey):
    signer = PKCS1_v1_5.new(privateKey)
    digest = SHA.new()
    digest.update(message)
    return signer.sign(digest)


def verify(message, signature, publicKey):
    signer = PKCS1_v1_5.new(publicKey)
    digest = SHA.new()
    digest.update(message)
    return signer.verify(digest, signature)


def keyToPem(key):
    return key.save_pkcs1().decode('utf8')


def printToFile(fileName, data):
    with open("./" + fileName, 'w') as the_file:
        print(data, file=the_file)
        the_file.close()


if __name__ == '__main__':
    keySize = 512
    publicKey, privateKey = rsa.newkeys(keySize)

    # stari kod
    plaintext = b"Hello Tony, I am Jarvis!"
    msg2 = b"Hello Toni, I am Jarvis!"  # try to verify
    ciphertext = b64encode(rsa.encrypt(plaintext, publicKey))
    originalMessage = rsa.decrypt(b64decode(ciphertext), privateKey)
    signature = b64encode(rsa.sign(plaintext, privateKey, "SHA-1"))

    PUPem = publicKey.save_pkcs1().decode()
    PUReloaded = rsa.PublicKey.load_pkcs1(PUPem.encode())

    PRPem = privateKey.save_pkcs1().decode()
    PRReloaded = rsa.PrivateKey.load_pkcs1(PRPem.encode())

    printToFile("privateKey.pem", PRPem)
    print("Encrypted: " + ciphertext.decode())
    print("Decrypted: '%s'" % originalMessage)
    printToFile("signature.txt", signature)

    verify = rsa.verify(plaintext, b64decode(signature), publicKey)
    print("Verify: %s" % verify)
    try:
        test = rsa.verify(msg2, b64decode(signature), publicKey)
    except Exception:
        print("Can not verify !")
