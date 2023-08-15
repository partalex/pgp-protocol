import json


class FileJSON:
    @staticmethod
    def writeToFile(data, filename):
        json_object = json.dumps(data, indent=4)

        with open(filename + ".JSON", "w") as outfile:
            outfile.write(json_object)

    @staticmethod
    def readFromFile(filename):
        with open(filename + ".JSON", "r") as read_file:
            data = json.load(read_file)
        return data


if __name__ == '__main__':
    data = {
        "name": "sathiyajith",
        "rollno": 56,
        "cgpa": 8.6,
        "phonenumber": "9976770500"
    }
    filename = "data"

    FileJSON.writeToFile(data, filename)
    print(FileJSON.readFromFile(filename))
