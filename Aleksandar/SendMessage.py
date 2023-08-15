from Cryptodome.Random import get_random_bytes

from Message import Message

if __name__ == '__main__':
    filename = 'FromAleksandarToMarko'
    plaintext = "Da li ovo radi? Ako radi, Marko neka nastavi sa radom."
    info = {  # read from file
        'symmetric': 'AES128',  # can be 'None', '3DES', 'AES128'
        '3DES': {
            'key': get_random_bytes(24).hex(),  # if symmetric is '3DES',
            'ivCBC': '\0\0\0\0\0\0\0\0',  # if symmetric is '3DES
        },
        'AES128': {
            'key': get_random_bytes(16).hex(),  # if symmetric is 'AES128'
        },
        'wantSHA1': True,  # or False
        'wantCompression': True,  # or False
        'wantRadix64': True  # or False
    }

    Message.send(plaintext, filename, info)  # cipher text is saved to file
