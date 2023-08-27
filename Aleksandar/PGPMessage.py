from Cryptodome.Random import get_random_bytes

from Aleksandar.Radix64 import Radix64
from Timestamp import Timestamp
from SHA1 import SHA1
from RSA import RSA
from ElGamal import ElGamal
from Compression import Compression
from TripleDES import TripleDES
from AES128 import AES128
from DSA import DSA


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
    def send(filename, message, authentication, encryption, signature, senderPrivateKey=None,
             receiverPublicKey=None, savePath="./resources/ReceiveInfo"):
        # 0. Prepare message.                              # Required
        # Add timestamp to the message.
        # Add file name to the message.

        timestamp = Timestamp().generateInBytes()
        message = timestamp + message
        message = filename.encode('utf-8') + message

        # 1.Authentication = Signing                        # Optional
        # Hash algorithm [SHA-1, NONE]. Ne
        # Result of the hash function is 160 bit value.
        # Protect hash value with PrivateKeySender [RSA, ElGamal, NONE]
        # Save last 4 bytes (64 bit) of PublicKey that is pair of PrivateKeySender.
        # Last 4 bytes of PublicKey is called KeyID and is calculated with mod 264.
        # Public key of the receiver [RSA, ElGamal, NONE].
        # Get it from the keyring with the receiver's ID or take first one.
        # Concatenate encrypted Hash and Message

        hashedDigest = SHA1().sign(message)
        match authentication:
            case "RSA":
                encryptedHash = RSA(senderPrivateKey, hashedDigest).getCiphertext()
            case "DSA":
                encryptedHash = DSA(senderPrivateKey, hashedDigest).getSignature()
            case "NONE":
                encryptedHash = b""
            case _:
                raise Exception("Invalid algorithm.")

        message = encryptedHash + message

        # 2.Compression [Compression, NONE]                 # Required
        # Compress Message
        message = Compression.compress(message)

        # 3. Encryption                                     # Optional
        # Symmetric encryption, block cipher, CBC mode
        # SymmetricKey random 128 bit value. One time use.
        # CAST-129 to generate SymmetricKey.
        # SymmetricKey is encrypted with Public Key of the receiver [RSA, ElGamal, NONE].
        # SymmetricKey = None  # Symmetric key [AES, DES, 3DES, NONE]
        # Concatenate encrypted SymmetricKey and Message.

        symmetricKey = "Symmetric or Session key has not chosen yet."

        match encryption:
            case "3DES":
                symmetricKey = get_random_bytes(24)
                message = TripleDES(symmetricKey, message).getCiphertext()
                # raise NotImplementedError
            case "AES128":
                symmetricKey = get_random_bytes(16)
                message = AES128(symmetricKey, message).getCiphertext()
                # raise NotImplementedError
            case "NONE":
                pass
            case _:
                raise Exception("Invalid algorithm.")

        match signature:
            case "RSA":
                encryptedSymmetricKey = RSA(receiverPublicKey, symmetricKey).getCiphertext()
            case "ElGamal":
                encryptedSymmetricKey = ElGamal(receiverPublicKey, symmetricKey).getCiphertext()
            case "NONE":
                encryptedSymmetricKey = b""
            case _:
                raise Exception("Invalid algorithm.")

        message = encryptedSymmetricKey + message

        # 4. Convert to radix64                             # Required
        message = Radix64.encodeBytes(message)

    @staticmethod
    def receive(savePath="./resources/ReceiveInfo"):
        # Load message info.
        message = "Load message from file."

        # 4. Convert from radix64                       # Required
        message = Radix64.decodeToBytes(message)

        # 3. Decryption                                 # Optional
        # Decrypt SymmetricKey with PrivateKeyReceiver [RSA, ElGamal, NONE]
        # Decrypt Message with decrypted SymmetricKey [AES, DES, 3DES, NONE]

        match signature:
            case "RSA":
                raise NotImplementedError
            case "ElGamal":
                raise NotImplementedError
            case "NONE":
                pass
            case _:
                raise Exception("Invalid algorithm.")

        # 2. Decompress Message [Compression, NONE]     # Required
        message = Compression.decompress(message)

        # 1. Authentication                             # Optional
        # Decrypt Hash with PublicKeySender [RSA, ElGamal, NONE]
        # Hash Message and compare with decrypted Hash
        # If they are not equal, message is corrupted.
        # If they are equal, message is not corrupted.

        match authentication:
            case "RSA":
                raise NotImplementedError
            case "ElGamal":
                raise NotImplementedError
            case "NONE":
                pass
            case _:
                raise Exception("Invalid algorithm.")

        return message


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
