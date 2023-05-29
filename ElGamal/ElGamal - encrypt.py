from Cryptodome import Random
from Cryptodome.PublicKey import ElGamal
import random

from Cryptodome.Util.number import GCD

# dokumentacija
# https://github.com/Legrandin/pycryptodome/blob/0701df338c1cc13b7376daa0a3592721de6d1959/lib/Crypto/PublicKey/ElGamal.py#L255

message = b"Hello!"

key = ElGamal.generate(512, Random.new().read)

while 1:
    k = random.randint(1, key.p - 1)

    if GCD(k, key.p - 1) == 1:
        break

# ove metode (encrypt, decrypt) ne rade
h = key.encrypt(message, k)
d = key.decrypt(h)
print(d)

# pronasao sam nesto tipa ovog ElGamal.ElGamalKey.publickey, pogledati da li moze da se iskoristi
ret = ElGamal.ElGamalKey.publickey(key)
