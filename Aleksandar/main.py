from Cryptodome.Random import get_random_bytes

from Aleksandar.Message import Message

if __name__ == '__main__':
    info = {  # read from file
        'symmetric': '3DES',  # can be 'None', '3DES', 'AES128'
        '3DES': {
            'key': get_random_bytes(24),  # if symmetric is '3DES',
            'ivCBC': '\0\0\0\0\0\0\0\0',  # if symmetric is '3DES
        },
        'AES128': {
            'key': get_random_bytes(16),  # if symmetric is 'AES128'
        },
        'wantSHA1': True,  # or False
        'SHA1': {
            'signature': 'Aleksandar Vasilic'.encode('utf-8')  # if wantSHA1 is True
        },
        'wantCompression': True,  # or False
        'wantRadix64': True  # or False
    }

    filename = 'test'
    plaintext = "Da li ovo radi? Ako radi, Marko neka nastavi sa radom."

    Message.send(plaintext, filename, info)  # cipher text is saved to file

    print(Message.receive(filename, info))
