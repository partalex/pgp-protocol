import base64

from Cryptodome.Random import get_random_bytes

from Radix64 import Radix64
from Timestamp import Timestamp
from SHA1 import SHA1
from RSA import RSA
from ElGamal import ElGamal
from Compression import Compression
from TripleDES import TripleDES
from AES128 import AES128
from DSA import DSA
from DictBytes import DictBytes


class PGPMessage:

    @staticmethod
    def getSupportAlgorithms():
        return {
            "authentication":
                ["RSA", "DSA", "NONE"],
            "encryption":
                ["3DES", "AES128", "NONE"],
            "signature":
                ["RSA", "ElGamal", "NONE"]

        }

    @staticmethod
    def send(
            filename, data,
            authentication_alg, encryption_alg, signature_alg,
            authentication_key=None, encryption_key=None, signature_key=None,
            savePath="./resources/ReceiveInfo"
    ):

        # 0. Prepare message.                              # Required
        # Add timestamp to the message.
        # Add file name to the message.

        messageDict = {
            "Timestamp": Timestamp().generateString(),
            "Filename": filename,
            "Data": data
        }

        # 1.Authentication = Signing                        # Optional

        messageBytes = DictBytes.dictToBytes(messageDict)
        messageDigest = SHA1().sign(messageBytes)
        match authentication_alg:
            case "RSA":
                authentication_key = RSA.importPrivateKey(authentication_key)
                messageDigestSigned = RSA.signAndExport(messageDigest.encode('utf-8'), authentication_key)
            case "DSA":
                authentication_key = DSA.importKey(authentication_key)
                messageDigestSigned = DSA.sign(messageDigest.encode('utf-8'), authentication_key)
            case "NONE":
                messageDigestSigned = b""
            case _:
                raise Exception("Invalid algorithm.")

        signatureDict = {
            "Message": messageDict,
            "Message Digest": messageDigestSigned,
            "Authentication algorithm": authentication_alg,
            # "keyIdOfSendersPublicKey": senderPrivateKey[-4:],
            # "leadingTwoOctetsOfMessageDigest": messageDigest[:2],
            "Timestamp": Timestamp().generateString()
        }

        # 2.Compression                                     # Required
        signatureBytes = DictBytes.dictToBytes(signatureDict)

        signatureCompressed = Compression.compress(signatureBytes)

        # 3. Encryption                                     # Optional

        match encryption_alg:
            case "3DES":
                encryption_key = TripleDES.importKey(encryption_key)
                signatureMessageCompressedEncrypted = TripleDES.encryptAndExport(encryption_key, signatureCompressed)
            case "AES128":
                encryption_key = AES128.encryptAndExport(signatureCompressed, encryption_key)
            case "NONE":
                signatureMessageCompressedEncrypted = signatureCompressed
                pass
            case _:
                raise Exception("Invalid algorithm.")

        match signature_alg:
            case "RSA":
                encryptedSessionKey = RSA.encrypt(encryption_key, signature_key)
                keyId = signature_key.n % 2 ** 32
            case "ElGamal":
                encryptedSessionKey = ElGamal.encrypt(signature_key, encryption_key.y, encryption_key.g,
                                                      encryption_key.p)
                keyId = encryption_key.y % 2 ** 32
            case "NONE":
                keyId = ""
                encryptedSessionKey = b""
            case _:
                raise Exception("Invalid algorithm.")

        sessionComponentDict = {
            "Message": signatureMessageCompressedEncrypted.hex(),
            "Session key": encryptedSessionKey.hex(),
            "Encryption algorithm": encryption_alg,
            "Signature algorithm": signature_alg,
            "Key Id": keyId
        }

        sessionComponentBytes = DictBytes.dictToBytes(sessionComponentDict)

        # 4. Convert to radix64                             # Required
        R64Bytes = Radix64.encodeBytes(sessionComponentBytes)

        return R64Bytes

    @staticmethod
    def receive(ciphertext, keyRing, savePath="./resources/ReceiveInfo"):
        # Load message info.
        # ciphertext = "Load message from file." # TODO

        # 4. Convert from radix64                       # Required
        sessionComponentBytes = Radix64.decodeToBytes(ciphertext)
        sessionComponentDict = DictBytes.bytesToDict(sessionComponentBytes)

        # 3. Decryption                                 # Optional
        # Decrypt SymmetricKey with PrivateKeyReceiver [RSA, ElGamal, NONE]
        # Decrypt Message with decrypted SymmetricKey [AES, DES, 3DES, NONE]

        signature_alg = sessionComponentDict["Signature algorithm"]
        keyId = sessionComponentDict["Key id"]
        signature_key = keyRing.getPrivateKeyByKeyId(keyId)
        encryptedSessionKey = sessionComponentDict["Session key"]

        match signature_alg:
            case "RSA":
                sessionKey = RSA.importPrivateKey(encryptedSessionKey)
                encryption_key = RSA.decrypt(sessionKey, signature_key)
                raise NotImplementedError
            case "ElGamal":
                encryption_key = ElGamal.decrypt(sessionComponentDict["Session key"], signature_key)
                raise NotImplementedError
            case "NONE":
                pass
            case _:
                raise Exception("Invalid algorithm.")

        encryption_alg = sessionComponentDict["Encryption algorithm"]

        match encryption_alg:
            case "3DES":
                raise NotImplementedError
            case "AES128":
                raise NotImplementedError
            case "NONE":
                pass
            case _:
                raise Exception("Invalid algorithm.")

        # 2. Decompress Message [Compression, NONE]     # Required
        signatureCompressed = Compression.decompress(sessionComponentBytes)

        # 1. Authentication                             # Optional
        signatureDict = DictBytes.bytesToDict(signatureCompressed)

        authentication_alg = signatureDict["Authentication algorithm"]
        messageDigestSigned = signatureDict["Message Digest"]
        messageDict = signatureDict["Message"]

        match authentication:
            case "RSA":
                messageDigest = RSA.verify(messageDict, messageDigestSigned, signature_key)
            case "ElGamal":
                raise NotImplementedError
            case "NONE":
                messageDigest = True
            case _:
                raise Exception("Invalid algorithm.")

        messageBytes = DictBytes.dictToBytes(messageDict)
        # verify message digest

        return messageDigest


if __name__ == '__main__':
    plaintext = b"Hello Tony, I am Jarvis!"
    userId = "avasilic99@gmail.com"

    # Test 1. {NONE, NONE, NONE}
    authentication = "NONE"  # [RSA, DSA, NONE]
    encryption = "NONE"  # [3DES, AES128, NONE]
    signature = "NONE"  # [RSA, ElGamal, NONE] # if encryption is NONE, signature must be NONE too.

    filePath = PGPMessage.send(userId, "test.txt", plaintext, authentication, encryption, signature).decode('utf-8')
    print(PGPMessage.receive(filePath).decode('utf-8'))

    # Test 2. {RSA, 3DES, RSA}
    # Test 3. {DSA, AES128, RSA}
    # Test 3. {RSA, 3DES, ElGamal}
