import json

from Cryptodome.Random import get_random_bytes


class FileManager:
    @staticmethod
    def jsonWriteToFile(filename, data):
        json_object = json.dumps(data, indent=4)

        with open(filename + ".JSON", "w") as outfile:
            outfile.write(json_object)

    @staticmethod
    def jsonReadFromFile(filename):
        with open(filename + ".JSON", "r") as read_file:
            data = json.load(read_file)
        return data

    @staticmethod
    def writeToFile(filenameWithExtension, data):
        with open(filenameWithExtension, 'w') as outfile:
            print(data, file=outfile)
            outfile.close()

    @staticmethod
    def readFromFile(filenameWithExtension):
        with open(filenameWithExtension, 'r') as infile:
            data = infile.read()
            infile.close()
        return data


if __name__ == '__main__':
    test = {  # read from file
        'symmetric': '3DES',  # can be 'None', '3DES', 'AES128'
        '3DES': {
            'key': get_random_bytes(24).hex(),  # if symmetric is '3DES',
            'ivCBC': '\0\0\0\0\0\0\0\0',  # if symmetric is '3DES
        },
        'AES128': {
            'key': get_random_bytes(16).hex(),  # if symmetric is 'AES128'
        },
        'wantSHA1': True,  # or False
        # 'SHA1': {
        #     'signature': 'Aleksandar Vasilic'  # if wantSHA1 is True
        # },
        'wantCompression': True,  # or False
        'wantRadix64': True  # or False
    }
    filenameTest = "TestJSON"

    FileManager.jsonWriteToFile(filenameTest, test)
    print(FileManager.jsonReadFromFile(filenameTest))
