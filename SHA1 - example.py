import hashlib

# https://docs.python.org/3/library/hashlib.html

hash_object = hashlib.sha1(b'HelWorld')
pbHash = hash_object.hexdigest()
length = len(pbHash.decode("hex"))
print(length)
