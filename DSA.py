# https://pycryptodome.readthedocs.io/en/latest/src/public_key/dsa.html

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import DSA
from Cryptodome.Signature import DSS

# Create a new DSA key
key = DSA.generate(2048)
f = open("public_key.pem", "wb")
f.write(key.publickey().export_key())
f.close()

# Sign a message
message = b"Hello"
hash_obj = SHA256.new(message)
signer = DSS.new(key, 'fips-186-3')
signature = signer.sign(hash_obj)

# Load the public key
f = open("public_key.pem", "r")
hash_obj = SHA256.new(message)
pub_key = DSA.import_key(f.read())
verifier = DSS.new(pub_key, 'fips-186-3')

# Verify the authenticity of the message
try:
    verifier.verify(hash_obj, signature)
    print("The message is authentic.")
except ValueError:
    print("The message is not authentic.")
