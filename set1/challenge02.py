# Fixed XOR

from utils.fixed_xor import fixed_xor
from utils.hex_to_bytes import decode_hex

def validate_implementation():
    """
    Validate the decoding and the xor of two strings
    produces the expeted result
    """
    t1_hex = "1c0111001f010100061a024b53535009181c"
    t2_hex = "686974207468652062756c6c277320657965"
    
    res_hex = "746865206b696420646f6e277420706c6179"

    t1 = decode_hex(t1_hex)
    t2 = decode_hex(t2_hex)

    res = fixed_xor(t1, t2)

    if decode_hex(res_hex) == res:
        print("Implementation is correct")


if __name__ == "__main__":
    validate_implementation()