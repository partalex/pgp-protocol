from datetime import datetime


class Timestamp:
    @staticmethod
    def generate():
        return datetime.now()

    @staticmethod
    def generateString():
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    def generateInBytes(self):
        return self.generateString().encode('utf-8')

    @staticmethod
    def generateStringWithoutMs():
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


if __name__ == "__main__":
    print(Timestamp.generateString() + " koak")
    print(Timestamp.generate())
    print(Timestamp.generateString())
    print(Timestamp.generateStringWithoutMs())
