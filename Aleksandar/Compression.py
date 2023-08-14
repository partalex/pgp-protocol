import zlib

data = "Ovaj string je    kompresovan    zlib-om !!!!"
print(data)

dataCompressed = zlib.compress(data.encode())
print(dataCompressed)

dataOriginal = zlib.decompress(dataCompressed)
print(dataOriginal.decode())
