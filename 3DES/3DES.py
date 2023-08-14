from pyDes import *

if __name__ == '__main__':
    key = "1234567_1234567_1234567_"  # can be 16B or 24B
    iv = "12345678"
    plaintext = "Please encrypt my data with 24B key."

    temp = triple_des(key, CBC, iv, pad=None, padmode=PAD_PKCS5)
    cipher = temp.encrypt(plaintext)

    originalText24B = temp.decrypt(cipher)
    print("Plaintext:", plaintext)
    print("Cipher:", cipher)
    print("Original message:", originalText24B.decode())

