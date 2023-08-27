import base64
import json


class DictBytes:
    @staticmethod
    def dictToBytes(input_dict):
        message = str(input_dict)
        ascii_message = message.encode('utf-8')
        output_byte = base64.b64encode(ascii_message)
        return output_byte

    @staticmethod
    def bytesToDict(input_byte):
        msg_bytes = base64.b64decode(input_byte)
        ascii_msg = msg_bytes.decode('utf')
        ascii_msg = ascii_msg.replace("'", "\"")
        output_dict = json.loads(ascii_msg)
        return output_dict


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
