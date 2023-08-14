import zlib


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


# Example
# data = "Ovaj string je    kompresovan    zlib-om !!!!"
# print(data)
#
# dataCompressed = Compression.compressString(data)
# print(dataCompressed)
#
# dataOriginal = Compression.decompressToString(dataCompressed)
# print(dataOriginal)
