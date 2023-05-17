import struct

def toRadix64(data):
    # paziti da li je data strign ili niz bajtova
    # https://stackoverflow.com/questions/5305456/python-how-do-i-convert-from-binary-to-base-64-and-back
    return struct.pack('I', data).encode('base64')

