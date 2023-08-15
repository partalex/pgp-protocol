from Aleksandar.AES128 import AES128
from Aleksandar.Radix64 import Radix64
from Aleksandar.Compression import Compression
from Aleksandar.TripleDES import TripleDES
from Aleksandar.FileJSON import FileJSON
from Aleksandar.SHA1 import SHA1


class Message:

    @staticmethod
    def send(plaintext, filename, info):
        ciphertext = plaintext.encode('utf-8')
        encryptionInfo = {}

        print('1. Security - which symmetric algorithm is chosen:' + info['symmetric'])
        match info['symmetric']:
            case '3DES':
                print('Message secured with 3DES encryption')
                ciphertext = TripleDES.encrypt(ciphertext, info['3DES']['key'], info['3DES']['ivCBC'])
            case 'AES128':
                print('Message secured with AES128 encryption')
                ciphertext = AES128.encrypt(ciphertext, info['AES128']['key'])
            case _:
                print('Message not secured')

        print('2. Authentication:')
        if info['wantSHA1']:
            signatureSHA1 = SHA1.sign(ciphertext)
            encryptionInfo['signatureSHA1'] = signatureSHA1
            encryptionInfo['wantSHA1'] = True
            print('Message is signed with SHA1. Signature: ' + signatureSHA1)

        print('3. Compression:')
        if info['wantCompression']:
            ciphertext = Compression.compressBytes(ciphertext)
            encryptionInfo['wantCompression'] = True

        print('4. Convert to radix64:')
        if info['wantRadix64']:
            ciphertext = Radix64.encodeBytes(ciphertext)
            encryptionInfo['wantRadix64'] = True

        print('5. Save to file:')
        encryptionInfo['info'] = info
        encryptionInfo['ciphertext'] = ciphertext
        encryptionInfo['plaintext'] = plaintext
        FileJSON.writeToFile(filename, encryptionInfo)

        return ciphertext

    @staticmethod
    def receive(filename, info):

        print("5. Read from file:")
        data = FileJSON.readFromFile(filename)
        info = data['info']
        plaintext = data['ciphertext']

        with open(filename + '.txt', 'r') as file:
            plainText = file.read()
        print('Message read from file ' + filename + '.txt')

        print("4. Convert from radix64:")
        if info['wantRadix64']:
            plainText = Radix64.decodeToBytes(plainText)

        print("3. Decompression:")
        if info['wantCompression']:
            plainText = Compression.decompressToBytes(plainText)

        print("2. Authentication:")
        if info['wantSHA1']:
            if SHA1.verify(plainText, info['signatureSHA1']):
                print('Message is verified with SHA1')
            else:
                print('Message is not verified with SHA1')

        print("1. Security:")
        match info['symmetric']:
            case 'None':
                print('Message received without encryption')
            case '3DES':
                print('Message received with 3DES encryption')
                plainText = AES128.decrypt(plainText, info['3DES']['key'])
            case 'AES128':
                print('Message received with AES128 encryption')
                plainText = TripleDES.decrypt(plainText, info['AES128']['key'])

        print('Message: ' + plainText)
