import hashlib


class SHA1:
    @staticmethod
    def signString(message):
        return hashlib.sha1(message.encode('utf-8')).hexdigest()

    @staticmethod
    def sign(message):
        return hashlib.sha1(message).hexdigest()


    @staticmethod
    def verify(message, signature):
        hash_obj = hashlib.sha1(message.encode('utf-8'))
        return hash_obj.hexdigest() == signature


if __name__ == '__main__':
    message = "Hello Tony, I am Jarvis!"
    print("Message: " + message)

    signature = SHA1.signString(message)
    print("Signature: " + signature)

    print("Verify: " + str(SHA1.verify(message, signature)))
