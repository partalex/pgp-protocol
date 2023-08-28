from Crypto.Random import get_random_bytes

from KeyRing import KeyRing
from FileManager import FileManager
from PGPMessage import PGPMessage

if __name__ == "__main__":
    listKeysInfo = FileManager.jsonReadFromFile("./resources/KeyRingInfo")

    # Initialise keyring.
    keyRing = KeyRing()
    for keyInfo in listKeysInfo:
        if keyInfo["Type"] == "RSA":
            keyRing.generateRSAKeys(keyInfo["Key size"], keyInfo["User Id"], keyInfo["Password"])
        elif keyInfo["Type"] == "ElGamal":
            keyRing.generateElGamalKeys(keyInfo["Key size"], keyInfo["User Id"], keyInfo["Password"])
        elif keyInfo["Type"] == "DSA":
            keyRing.generateDSAKeys(keyInfo["Key size"], keyInfo["User Id"], keyInfo["Password"])
        else:
            raise Exception("Invalid key type.")
    # keyRing.print()
    # exit(0)

    # Load message info.
    inputInfo = "./resources/SendInfo"
    sendInfo = FileManager.jsonReadFromFile(inputInfo)

    # Prepare parameters.
    message = sendInfo['Message']
    output = sendInfo['Output']
    authentication_alg = sendInfo['Authentication algorithm']  # [RSA, DSA, NONE].
    signature_alg = sendInfo['Signature algorithm']  # [RSA, ElGamal, DSA), NONE]
    encryption_alg = sendInfo['Encryption algorithm']  # [3DES, AES128, NONE]
    savePath = sendInfo['Save path']

    authentication_key = keyRing.ring[0]['Private key']  # [{RSA}, DSA, NONE]
    authentication_key_id = keyRing.ring[0]['Key Id']  # [{RSA}, DSA, NONE]

    signature_key = get_random_bytes(24)  # [{3DES}, AES128, NONE]
    encryption_key = keyRing.ring[0]['Public key']  # [{RSA}, ElGamal, NONE]

    # Send message.
    print("Message: " + message)
    print("Sending message...")
    ciphertext = PGPMessage.send(
        output, message,
        authentication_alg, signature_alg, encryption_alg,
        authentication_key, signature_key, encryption_key,
        savePath)  # TODO - Missing session key.

    # Receive message.
    originalMessage = PGPMessage.receive(ciphertext, keyRing)
    print()
    print("Received message: ")
    print(originalMessage)
