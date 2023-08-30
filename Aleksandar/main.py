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
    keyRing.print()

    test = 0

    if test == 0:
        input_info = "./resources/input_info_0"

    if test == 1:
        input_info = "./resources/input_info_1"

    # Test 2
    if test == 2:
        input_info = "./resources/input_info_2"

    send_info = FileManager.jsonReadFromFile(input_info)

    authentication_alg = send_info['Authentication algorithm']  # [RSA, DSA, NONE].
    signature_alg = send_info['Signature algorithm']  # [3DES, AES128, NONE]
    encryption_alg = send_info['Encryption algorithm']  # [RSA, (ElGamal, DSA), NONE]
    savePath = send_info['Save path']

    if test == 0:
        authentication_key = "No"
        authentication_key_id = "No"
        signature_key = "No"
        encryption_key = "No"

    if test == 1:
        authentication_key = keyRing.ring[0]['Private key']  # [{RSA}, DSA, NONE]
        authentication_key_id = keyRing.ring[0]['Key Id']
        signature_key = get_random_bytes(24)  # [{3DES}, AES128, NONE]
        encryption_key = keyRing.ring[0]['Public key']  # [{RSA}, ElGamal, NONE]

    if test == 2:
        authentication_key = keyRing.ring[2]['Private key']  # [RSA, {DSA}, NONE]
        authentication_key_id = keyRing.ring[2]['Key Id']
        signature_key = get_random_bytes(16)  # [3DES, {AES128}, NONE]
        encryption_key = keyRing.ring[1]['Public key']  # [RSA, {ElGamal}, NONE]

    message = send_info['Message']
    output = send_info['Output']

    # Send message.
    print("Message: " + message)
    print("Sending message...")

    ciphertext = PGPMessage.send(
        output, message,
        authentication_alg, signature_alg, encryption_alg,
        authentication_key, signature_key, encryption_key
        , savePath)

    # Receive message.
    originalMessage = PGPMessage.receive(ciphertext, keyRing)
    print()
    print("Received message: ")
    print(originalMessage)
