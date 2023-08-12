from pyDes import *

key16B = "1234567_1234567_"
key24B = "1234567_1234567_1234567_"

initVectorCBC = "12345678"

plaintext16B = "Please encrypt my data with 16B key."
plaintext24B = "Please encrypt my data with 24B key."

k16B = triple_des(key16B, CBC, initVectorCBC, pad=None, padmode=PAD_PKCS5)
k24B = triple_des(key24B, CBC, initVectorCBC, pad=None, padmode=PAD_PKCS5)

ciphertext16B = k16B.encrypt(plaintext16B)
ciphertext24B = k24B.encrypt(plaintext24B)

originalText16B = k16B.decrypt(ciphertext16B)
originalText24B = k24B.decrypt(ciphertext24B)

print("16B")
print("Plaintext message:", plaintext16B)
print("Cipher message:", ciphertext16B)
print("Original message:", originalText16B.decode())
print("24B")
print("Plaintext:", plaintext24B)
print("Cipher:", ciphertext24B)
print("Original message:", originalText24B.decode())

# assert k16B.decrypt(ciphertext16B, padmode=PAD_PKCS5) == plaintext
