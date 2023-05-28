from elgamal.elgamal import Elgamal

t = Elgamal.newkeys(18)

# num = randint(0, 50)
# pb = ElGamal.generate(2048, randint(0, 50))

m = b'Text'

print(m)

pb, pv = Elgamal.newkeys(128)

print(pb)
print(pv)

ct = Elgamal.encrypt(m, pb)

print(ct)

dd = Elgamal.decrypt(ct, pv)

print(dd)