import hashlib


class SH1:
    @staticmethod
    def sign(message):
        hash_obj = hashlib.sha1(message.encode('utf-8'))
        return hash_obj.hexdigest()

    @staticmethod
    def verify(message, signature):
        hash_obj = hashlib.sha1(message.encode('utf-8'))
        return hash_obj.hexdigest() == signature


if __name__ == '__main__':
    message = "Hello Tony, I am Jarvis!"
    print("Message: " + message)

    signature = SH1.sign(message)
    print("Signature: " + signature)

    print("Verify: " + str(SH1.verify(message, signature)))
