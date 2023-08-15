from AES128 import AES128
from Radix64 import Radix64
from Compression import Compression
from TripleDES import TripleDES
from FileJSON import FileJSON
from SHA1 import SHA1


class Message:

    @staticmethod
    def send(plaintext, filename, info):
        ciphertext = plaintext.encode('utf-8')
        encryptionInfo = {}
        # print text message
        print('0. Message:')
        print('\t' + plaintext)

        print('1. Symmetric encryption:')
        match info['symmetric']:
            case '3DES':
                print('\t1.1 Message is encrypted with 3DES. ')
                ciphertext = TripleDES.encrypt(ciphertext, bytes.fromhex(info['3DES']['key']), info['3DES']['ivCBC'])
            case 'AES128':
                print('\t1.1 Message is encrypted with AES128.')
                data = AES128.encrypt(ciphertext, bytes.fromhex(info['AES128']['key']))
                ciphertext = data['ciphertext']
                info['AES128']['iv'] = data['iv'].decode('utf-8')
            case _:
                print('\t1.1 Message is not encrypted.')

        print('2. Authentication:')
        if info['wantSHA1']:
            signatureSHA1 = SHA1.sign(ciphertext)
            info['signatureSHA1'] = signatureSHA1
            print('\t2.1 Message is signed with SHA1.')

            print('3. Compression:')
            if info['wantCompression']:
                ciphertext = Compression.compress(ciphertext)
                print('\t3.1 Message is compressed.')

            print('4. Convert to radix64:')
            if info['wantRadix64']:
                ciphertext = Radix64.encodeBytes(ciphertext)
                print('\t4.1 Message is converted to radix64.')

            print('5. Save to file:')
            info['ciphertext'] = ciphertext.decode('utf-8')
            info['plaintext'] = plaintext
            encryptionInfo['info'] = info
            FileJSON.writeToFile(filename, encryptionInfo)
            print('\t5.1 Message is saved to file.')

        return ciphertext

    @staticmethod
    def receive(filename):

        print("5. Read from file:")
        info = FileJSON.readFromFile(filename)['info']
        plaintext = info['ciphertext'].encode('utf-8')

        print("4. Convert from radix64:")
        if info['wantRadix64']:
            plaintext = Radix64.decodeToBytes(plaintext)

        print("3. Decompression:")
        if info['wantCompression']:
            plaintext = Compression.decompress(plaintext)

        print("2. Authentication:")
        if info['wantSHA1']:
            if SHA1.verify(plaintext, info['signatureSHA1']):
                print('Message is verified with SHA1')
            else:
                print('Message is not verified with SHA1')

        print("1. Security:")
        match info['symmetric']:
            case 'None':
                print('Message received without encryption')
            case '3DES':
                print('Message received with 3DES encryption')
                plaintext = TripleDES.decrypt(plaintext, bytes.fromhex(info['3DES']['key']), info['3DES']['ivCBC'])
            case 'AES128':
                print('Message received with AES128 encryption')
                plaintext = AES128.decrypt(plaintext, bytes.fromhex(info['AES128']['key']),
                                           info['AES128']['iv'].encode('utf-8'))

        return plaintext.decode('utf-8')
