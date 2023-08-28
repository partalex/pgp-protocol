import base64
import json


class DictBytes:
    @staticmethod
    def dictToBytes(inputDict):
        message = str(inputDict)
        ascii_message = message.encode('utf-8')
        output_byte = base64.b64encode(ascii_message)
        return output_byte

    @staticmethod
    def bytesToDict(inputDict) -> dict:
        msg_bytes = base64.b64decode(inputDict)
        ascii_msg = msg_bytes.decode('utf-8')
        ascii_msg = ascii_msg.replace("'", "\"")
        output_dict = json.loads(ascii_msg)
        return output_dict

    @staticmethod
    def dictToString(inputDict) -> str:
        DictBytes.dictToBytes(inputDict).decode('utf-8')


if __name__ == '__main__':
    print("-" * 50)

    input_dict = {
        'var1': 0,
        'var2': 'some string',
        'var3': ['listitem1', 'listitem2', 5]
    }

    print("input_dict:", input_dict, type(input_dict))
    print("-" * 50)

    bytes = DictBytes.dictToBytes(input_dict)
    print("bytes:", bytes, type(bytes))
    print("-" * 50)

    original_byte = DictBytes.bytesToDict(bytes)
    print("original_byte:", original_byte, type(original_byte))
    print("-" * 50)
