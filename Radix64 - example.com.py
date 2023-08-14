import base64


class Radix64:

    @staticmethod
    def encodeFromString(palintexString):
        palintexString = palintexString.encode('ascii')
        return Radix64.encodeBytes(palintexString)

    @staticmethod
    def encodeBytes(plaintextBytes):
        return base64.b64encode(plaintextBytes)

    @staticmethod
    def decodeToString(cipher):
        return base64.b64decode(cipher).decode('ascii')

    @staticmethod
    def decodeToBytes(cipher):
        return base64.b64decode(cipher)


print("Example with string:")
message = "Hello Tony, I am Jarvis!"
print("Message: " + message)

encoded = Radix64.encodeFromString(message)
print("Encoded: " + encoded.decode('ascii'))

decoded = Radix64.decodeToString(encoded)
print("Decoded: " + decoded)

print("\nExample with bytes:")

message = b"Hello Tony, I am Jarvis!"
print("Message: " + message.decode('ascii'))

encoded = Radix64.encodeBytes(message)
print("Encoded: " + encoded.decode('ascii'))

decoded = Radix64.decodeToBytes(encoded)
print("Decoded: " + decoded.decode('ascii'))
