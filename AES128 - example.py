from crypto.Cipher import AES
from crypto.Random import get_random_bytes

data = b'test podatak'

key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_MAX)
ciphertext, tag = cipher.encrypt_and_digest(data)
nonce = cipher.nonce
cipher = AES.new(key, AES.MODE_EAX, nonce)
data = cipher.decrypt_and_verify(ciphertext, tag)
print(data.decode())
