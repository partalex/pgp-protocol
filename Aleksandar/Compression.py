import zlib

data = "Ovaj string je    kompresovan    zlib-om !!!!"
print(data)

dataCompressed = zlib.compress(data.encode())
print(dataCompressed)

dataOriginal = zlib.decompress(dataCompressed)
print(dataOriginal.decode())


class Compression:
    @staticmethod
    def compressString(data):
        return zlib.compress(data.encode('utf-8'))

    @staticmethod
    def compressBytes(data):
        return zlib.compress(data)

    @staticmethod
    def decompressToString(data):
        return zlib.decompress(data).decode('utf-8')

    @staticmethod
    def decompressToBytes(data):
        return zlib.decompress(data)
