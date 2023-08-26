import rsa


class RSA:
    def __init__(self, key_size, plaintext):
        self.keySize = key_size
        self.plaintext = plaintext
        self.publicKey, self.privateKey = rsa.newkeys(self.keySize)
        self.ciphertext = self.__encrypt()

    def __int__(self, private_key, plaintext):
        self.privateKey = private_key
        self.plaintext = plaintext
        self.ciphertext = self.__encrypt()

    def __encrypt(self):
        return rsa.encrypt(self.plaintext, self.publicKey)

    def __decrypt(self):
        return rsa.decrypt(self.ciphertext, self.privateKey)

    def getCiphertext(self):
        return self.ciphertext

    def verify(self, plaintext):
        return self.__decrypt() == plaintext

    @staticmethod
    def __printToFile(filename, data):
        with open(filename, 'w') as the_file:
            print(data, file=the_file)
            the_file.close()

    @staticmethod
    def generateKeys(numberOfKeys, keySize):
        for i in range(1, numberOfKeys + 1):
            publicKey, privateKey = rsa.newkeys(keySize)
            PUPem = publicKey.save_pkcs1().decode()
            PRPem = privateKey.save_pkcs1().decode()
            # write to resources dir
            RSA.__printToFile("./resources/" + str(i) + ".publicKey.pem", PUPem)
            RSA.__printToFile("./resources/" + str(i) + ".privateKey.pem", PRPem)

            # RSA.__printToFile("./resources" + str(i) + ".publicKey.pem", PUPem)
            # RSA.__printToFile("./resources" + str(i) + ".privateKey.pem", PRPem)
            print("Generated " + str(i) + ".publicKey.pem and " + str(i) + ".privateKey.pem")


if __name__ == '__main__':
    RSA.generateKeys(4,2048)

    # message = b"Hello Tony, I am Jarvis!"
    # rsaObject = RSA(512, message)
    #
    # print("Message: " + message.decode('utf-8'))
    # print("Ciphertext: " + str(rsaObject.getCiphertext()))
    # print("Verify: " + str(rsaObject.verify(message)))
