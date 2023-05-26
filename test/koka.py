from Crypto.PublicKey import RSA

private_key = RSA.generate(1024)
public_key = private_key.publickey()
print(private_key.exportKey(format='PEM'))
print(public_key.exportKey(format='PEM'))

with open("./private.pem", "w") as file:
    print("{}".format(private_key.exportKey()), file=file)

with open("./public.pem", "w") as file:
    print("{}".format(public_key.exportKey()), file=file)

with open('./private_key.pem', 'rb') as file:
    pkeydata = file.read()
