# Break an MD4 keyed MAC using length extension

from primitives.md4 import MD4
import secrets
import struct

key = secrets.token_bytes(16)


def compute_mac(message):
    """
    Create a MD4 keyed MAC.
    """
    return MD4(key + message).hexdigest()

def verify_mac(message, mac):
    """
    Verify a MAC with the message and the key.
    """
    new_mac = compute_mac(message)

    return mac == new_mac


# Reference: http://www.practicalcryptography.com/hashes/md4-hash/
def compute_md_padding(message_len):
    """
    Compute the padding for MD4. The padded message is 64 bits
    less than a multiple of 512 and as the structure 
    0b1{0}^n for `n` missing bits.
    """
    ml = message_len * 8

    padding = b"\x80"   # 0b1000 0000 in binary
    padding += b"\x00" * ((56 - (message_len + 1) % 64) % 64) # 56 is 448 bits in bytes (512 - 64)
    padding += struct.pack("<Q", ml)

    return padding


def forge_message(original_message, original_mac):
    """
    Performs a length extension attack on a MD4 MAC.
    Allows to add valid blocks after the original MAC.
    """
    state = list(struct.unpack("<4L", original_mac))

    glue_padding = compute_md_padding(len(original_message) + 16)

    extension = b";admin=true"

    forged_message = original_message + glue_padding + extension

    extension_padding = compute_md_padding(
        16 + len(original_message) + len(glue_padding) + len(extension)
    )

    data_to_process = extension + extension_padding

    forged_state = MD4.md4_continue(data_to_process, state)

    # Serialize state as an MD4 digest (little endian)
    forged_mac = struct.pack("<4L", *forged_state).hex()

    return forged_message, forged_mac


def attack_construction():
    message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

    mac = compute_mac(message)
    mac_bytes = bytes.fromhex(mac)
    
    forged_message, forged_mac = forge_message(message, mac_bytes)

    if verify_mac(message, mac):
        print("Original mac is correct")

    if verify_mac(forged_message, forged_mac):
        print("Forged mac is correct")
        print("Successfully forged message:", forged_message)


if __name__ == "__main__":
    attack_construction()