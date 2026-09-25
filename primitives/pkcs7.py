# Reference: https://en.wikipedia.org/wiki/PKCS_7

def pkcs7_padding(msg, b_len):
    """
    Pad a message using the PKCS #7 padding
    """
    missing = b_len - (len(msg) % b_len)

    return msg + bytes([missing]) * missing

def pkcs7_unpadding(msg, block_len):
    """
    Unpad a message using the PKCS #7 padding
    """
    if len(msg) == 0 or len(msg) % block_len != 0:
        raise ValueError("Invalid padded message")

    padding_len = msg[-1]

    if padding_len < 1 or padding_len > block_len:
        raise ValueError("Invalid padding")

    if msg[-padding_len:] != bytes([padding_len]) * padding_len:
        raise ValueError("Invalid padding")

    return msg[:-padding_len]