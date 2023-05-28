from elgamal.elgamal import Elgamal

m = b'Text'

print(m)

pb, pv = Elgamal.newkeys(128)

print(pb)
print(pv)

ct = Elgamal.encrypt(m, pb)

print(ct)

dd = Elgamal.decrypt(ct, pv)

print(dd)