# rsa
import rsa

(pubkey, privkey) = rsa.newkeys(512, poolsize=4)

message = b'Say hi!'
crypto = rsa.encrypt(message, pubkey)

PRIV_KEY_DST = 'your path to file'
with open(PRIV_KEY_DST, 'wb+') as f:
    pk = rsa.PrivateKey.save_pkcs1(privkey, format='PEM')
    f.write(pk)
