# Hashing with CBC-MAC

from primitives.aes_cbc import new_iv
from primitives.cbc_mac import create_mac, validate_mac, BLOCK_SIZE
from utils.fixed_xor import fixed_xor


key = b'YELLOW SUBMARINE'
iv = b'\x00' * BLOCK_SIZE


def validate():
    """
    Validate we get the expected 'hash' for the
    message.
    """
    msg = b"alert('MZA who was that?');\n"
    hash = create_mac(msg, iv, key)

    assert hash.hex() == '296b8d7cb78a243dda4d0a61d33bbdd1'


def forge_mac():
    """
    We'll use javascript comments to add some bytes
    after our alert message (they won't get interpreted).

    The forged message has this structure:
    our_message || padding || crafted_block || target[1:]

    The crafted block is chosen so that, when CBC-MAC processes it,
    the input to AES is identical to the input used for the first
    block of the target message.

    If H is the CBC-MAC of our_message, we choose:
    crafted_block = H XOR target_block_1
    """
    target_msg = b"alert('MZA who was that?');\n"

    # The alert message we want to execute
    msg = b"alert('Ayo, the Wu is back!');//"
    hash = create_mac(msg, iv, key)

    # Here we craft our message
    next_block = fixed_xor(hash, target_msg[:BLOCK_SIZE])    
    msg += b'\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
    msg += next_block
    msg += target_msg[BLOCK_SIZE:]

    print("Crafted message:", msg)

    hash = create_mac(msg, iv, key)
    if hash.hex() == '296b8d7cb78a243dda4d0a61d33bbdd1':
        print("Successfully forged the 'hash'")


if __name__ == "__main__":
    validate()
    forge_mac()