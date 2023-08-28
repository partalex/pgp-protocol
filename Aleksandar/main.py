from Crypto.Random import get_random_bytes

from KeyRing import KeyRing
from FileManager import FileManager
from PGPMessage import PGPMessage

if __name__ == "__main__":
    listKeysInfo = FileManager.jsonReadFromFile("./resources/KeyRingInfo")

    # Load keyring.
    keyRing = KeyRing()
    for keyInfo in listKeysInfo:
        if keyInfo["type"] == "RSA":
            keyRing.generateRSAKeys(keyInfo["keySize"], keyInfo["userId"], keyInfo["password"])
        elif keyInfo["type"] == "DSA":
            keyRing.generateDSAKeys(keyInfo["keySize"], keyInfo["userId"], keyInfo["password"])
        else:
            raise Exception("Invalid key type.")
    # keyRing.print()
    # exit(0)

    # Load message info.
    inputInfo = "./resources/SendInfo"
    sendInfo = FileManager.jsonReadFromFile(inputInfo)

    # Prepare parameters.
    message = sendInfo['message']
    output = sendInfo['output']
    authentication_alg = sendInfo['authentication_alg']  # [RSA, DSA, NONE].
    encryption_alg = sendInfo['encryption_alg']  # [3DES, AES128, NONE] # Optional.
    signature_alg = sendInfo['signature_alg']  # [RSA, ElGamal, DSA), NONE]
    # If encryption is DSA here is ElGamal.
    # If encryption is NONE, here NONE too.
    # senderPrivateKey = sendInfo['senderPrivateKey']
    # receiverPublicKey = sendInfo['receiverPublicKey']
    savePath = sendInfo['savePath']

    authentication_key = keyRing.ring[0]['Private key']  # [{RSA}, DSA, NONE]
    encryption_key = get_random_bytes(24)  # [{3DES}, AES128, NONE]
    signature_key = keyRing.ring[0]['Public key']  # [{RSA}, ElGamal, NONE]

    # Send message.
    ciphertext = PGPMessage.send(
        output, message,
        authentication_alg, encryption_alg, signature_alg,
        authentication_key, encryption_key, signature_key,
        savePath)  # TODO - Missing session key.

    # Receive message.
    originalMessage = PGPMessage.receive(ciphertext, keyRing)
