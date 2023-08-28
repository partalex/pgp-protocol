from rsa import VerificationError

from Aleksandar.KeyRing import KeyRing
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
            authentication_alg, signature_alg, encryption_alg,
            authentication_key=None, signature_key=None, encryption_key=None,
            savePath="./resources/ReceiveInfo"
    ):

        # 0. Prepare message.                                   # Required
        message_dict = {
            "Timestamp": Timestamp().generateString(),
            "Filename": filename,
            "Data": data
        }

        # 1. Message Digest                                     # Required
        message_bytes = DictBytes.dictToBytes(message_dict)
        message_digest = SHA1().hash(message_bytes)

        # 2. Authenticate message digest                        # Optional
        match authentication_alg:
            case "RSA":
                authentication_key = RSA.importPrivateKey(authentication_key)
                message_digest_signed = RSA.signAndExport(message_digest.encode('utf-8'), authentication_key)
                key_id = RSA.getKeyId(authentication_key)
            case "DSA":
                authentication_key = DSA.importKey(authentication_key)
                message_digest_signed = DSA.sign(message_digest.encode('utf-8'), authentication_key)
                key_id = DSA.getKeyId(authentication_key)
            case "NONE":
                message_digest_signed = b""
                key_id = ""
            case _:
                raise Exception("Invalid algorithm.")

        signature_message_dict = {
            "Timestamp": Timestamp().generateString(),
            "Key Id of sender Public key": key_id,
            "Leading two octets of message digest": message_digest[:2],
            "Authentication algorithm": authentication_alg,
            "Message Digest": message_digest_signed,
            "Message": message_dict
        }

        signature_message_bytes = DictBytes.dictToBytes(signature_message_dict)

        # 3. Compression                                            # Required
        # print decompressed_signature_message_bytes
        compressed_signature_message_bytes = Compression.compress(signature_message_bytes)

        # 4. Signing                                          # Optional
        match signature_alg:
            case "3DES":
                signature_key = TripleDES.importKey(signature_key)
                signed_compressed_signature_message = TripleDES.encryptAndExport(
                    compressed_signature_message_bytes,
                    signature_key)
            case "AES128":
                signature_key = AES128.encryptAndExport(compressed_signature_message_bytes, signature_key)
                signed_compressed_signature_message = AES128.encryptAndExport(compressed_signature_message_bytes,
                                                                              signature_key)
            case "NONE":
                signed_compressed_signature_message = compressed_signature_message_bytes.decode('utf-8')
                pass
            case _:
                raise Exception("Invalid algorithm.")

        encryption_data = {
            "Compress + signature + message": signed_compressed_signature_message,
            "Signature algorithm": signature_alg,
        }

        # 5. Encrypt Session key                                   # Optional
        match encryption_alg:
            case "RSA":
                encryption_key = RSA.importPublicKey(encryption_key)
                session_key = RSA.encryptAndExport(signature_key, encryption_key)
                key_id = RSA.getKeyId(encryption_key)
            case "ElGamal":
                encryption_key = ElGamal.importKey(encryption_key)
                session_key = ElGamal.encryptAndExport(signature_key, encryption_key)
                key_id = ElGamal.getKeyId(encryption_key)
            case "NONE":
                key_id = ""
                session_key = ""
            case _:
                raise Exception("Invalid algorithm.")

        final_dict = {
            "Key Id": key_id,
            "Session key": session_key,
            "Encryption algorithm": encryption_alg,
            "Inner data": encryption_data,
        }

        final_bytes = DictBytes.dictToBytes(final_dict)

        # 6. Convert to radix64                             # Required
        ciphertext = Radix64.encodeBytes(final_bytes)

        return ciphertext

    @staticmethod
    def receive(ciphertext, key_ring: KeyRing, savePath="./resources/ReceiveInfo"):
        # Load message info.
        # ciphertext = "Load message from file." # TODO

        # 6. Convert from radix64                       # Required
        final_bytes = Radix64.decodeToBytes(ciphertext)
        final_dict = DictBytes.bytesToDict(final_bytes)

        # 5. Encrypt Session key                                   # Optional
        encryption_alg = final_dict["Encryption algorithm"]
        session_key = final_dict["Session key"]
        encryption_data = final_dict["Inner data"]

        key_id = final_dict["Key Id"]
        verification_key = key_ring.getPrivateKeyByKeyId(key_id)

        match encryption_alg:
            case "RSA":
                verification_key = RSA.importPrivateKey(verification_key)
                signature_key = RSA.importAndDecrypt(session_key, verification_key)
            case "ElGamal":
                signature_key = ElGamal.importAndVerify(session_key, verification_key)
                raise NotImplementedError
            case "NONE":
                signature_key = session_key.encode('utf-8')
                pass
            case _:
                raise Exception("Invalid algorithm.")

        signature_alg = encryption_data["Signature algorithm"]
        compressed_signed_message = encryption_data["Compress + signature + message"]

        match signature_alg:
            case "3DES":
                signature_key = TripleDES.importKey(signature_key)
                compressed_signature_message_bytes = TripleDES.importAndDecrypt(compressed_signed_message,
                                                                                signature_key)
            case "AES128":
                compressed_signature_message_bytes = compressed_signed_message
                raise NotImplementedError
            case "NONE":
                compressed_signature_message_bytes = compressed_signed_message.encode('utf-8')
                pass
            case _:
                raise Exception("Invalid algorithm.")

        # 2. Decompress Message [Compression, NONE]     # Required
        signature_message_bytes = Compression.decompress(compressed_signature_message_bytes)

        # 1. Authentication                             # Optional
        signature_message_dict = DictBytes.bytesToDict(signature_message_bytes)

        authentication_alg = signature_message_dict["Authentication algorithm"]
        message_digest_signed = signature_message_dict["Message Digest"]
        key_id = signature_message_dict["Key Id of sender Public key"]
        message_dict = signature_message_dict["Message"]

        signature_key = key_ring.getPublicKeyByKeyId(key_id)
        message_bytes = DictBytes.dictToBytes(message_dict)

        match authentication_alg:
            case "RSA":
                signature_key = RSA.importPublicKey(signature_key)
                try:
                    message_digest = SHA1().hash(message_bytes)
                    ret = test_message_digest = RSA.importAndVerify(
                        message_digest.encode('utf-8'), message_digest_signed, signature_key)
                except VerificationError as e:
                    print(e)
            case "ElGamal":
                raise NotImplementedError
            case "NONE":
                messageDigest = True
            case _:
                raise Exception("Invalid algorithm.")

        return message_dict["Data"]


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
