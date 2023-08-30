import zlib


class Compression:
    @staticmethod
    def compressString(data):
        return zlib.compress(data.encode('utf-8'))

    @staticmethod
    def compress(data):
        return zlib.compress(data)

    @staticmethod
    def decompressToString(data):
        return zlib.decompress(data).decode('utf-8')

    @staticmethod
    def decompress(data):
        return zlib.decompress(data)


if __name__ == '__main__':
    dataString = "Ovaj string je kompresovan zlib-om !"
    print(dataString)

    dataCompressed = Compression.compressString(dataString)
    print(dataCompressed)

    dataOriginal = Compression.decompressToString(dataCompressed)
    print(dataOriginal)

    print("--------------------------------------------------")

    dataBytes = b"Ovaj string je kompresovan zlib-om !"
    print(dataBytes)

    dataCompressed = Compression.compress(dataBytes)
    print(dataBytes)

    dataOriginal = Compression.decompress(dataCompressed)
    print(dataOriginal)
