from multiprocessing import freeze_support

import rsa

# name = input("Unesite ime : ")
# mail = input("Unesite mail : ")
# simetric_alg = input("Unesite simetricni algoritam : ")
# key_size = input("Velicina kljuca : ")
# password = input("Unesite lozinku : ")

if __name__ == '__main__':
    freeze_support()

    # name = "Aleksandar"
    # mail = "avasilic99@gmail.com"
    # encryption = {
    #     "1": "RSA_alone",
    #     "2": "ElGamal and DSA"
    # }
    # simetric_alg = "birati iz encryption"
    # password_for_PR = "mojaLozinkaZaPristupPR"
    # key_size = [1024, 2048]
    #
    # aleksandar = {
    #     "PR": None,
    #     "PU": None,
    #     "pass": None
    # }
    #
    # marko = {
    #     "PR": None,
    #     "PU": None,
    #     "pass": None
    # }
    #
    # (aleksandar["PU"], aleksandar["PR"]) = rsa.newkeys(key_size[0], poolsize=4)
    # (marko["PU"], marko["PR"]) = rsa.newkeys(key_size[0], poolsize=4)
    #
    # input_message = "mi smo pravi programeri"
    # input_message_in_bytes = bytes(input_message, "utf-8")
    #
    # M1 = rsa.encrypt(input_message_in_bytes, marko["PR"])
    # M2 = rsa.encrypt(M1, aleksandar["PU"])
    #
    # E2 = rsa.decrypt(M2, aleksandar["PR"])
    # E1 = rsa.decrypt(E2, marko["PU"])
    #
    # print(E1.decode())
