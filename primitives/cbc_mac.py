from primitives.aes_cbc import aes_cbc_encrypt, new_iv, BLOCK_SIZE
from utils.constant_time_compare import constant_time_compare

def create_mac(msg, iv, key):
    """
    Create a MAC with CBC-MAC.

    Encrypt the message with AES in CBC mode
    and only return the last block of the
    ciphertext.
    """
    ct = aes_cbc_encrypt(msg, key, iv)

    return ct[-BLOCK_SIZE:]


def validate_mac(msg, key, iv, mac):
    """
    Validate the MAC with CBC-MAC.
    """
    ct = aes_cbc_encrypt(msg, key, iv)

    expected = ct[-BLOCK_SIZE:]

    return constant_time_compare(mac, expected)