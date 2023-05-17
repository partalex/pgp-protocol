##### AES128 #####
# https://stackoverflow.com/questions/32160121/aes-128-in-python
# required package : pycryptodome
import binascii
import os

from crypto.Cipher import AES

key = binascii.unhexlify('1F61ECB5ED5D6BAF8D7A7068B28DCC8E')
IV = os.urandom(16)
binascii.hexlify(IV).upper()
b'3C118E12E1677B8F21D4922BE4B2398E'
encryptor = AES.new(key, AES.MODE_CBC, IV=IV)
text = binascii.unhexlify('020ABC00ABCDEFf8d500000123456789')
ciphertext = encryptor.encrypt(text)
print(binascii.hexlify(ciphertext).upper())
