# CBC bitflipping attacks

from primitives.aes_cbc import aes_cbc_decrypt, aes_cbc_encrypt, new_iv

prefix = b"comment1=cooking%20MCs;userdata="
postfix = b";comment2=%20like%20a%20pound%20of%20bacon"

key = b"YELLOW SUBMARINE"

def parse_kv(s):
    """
    Parses the cookie to get the key-value
    pairs.
    """
    profile = {}

    for pair in s.split(b";"):
        key, value = pair.split(b"=", 1)
        profile[key] = value

    return profile

def profile_for(input):
    """
    Create a cookie for a given email
    """
    input = input.replace(b";", b"").replace(b"=", b"")

    profile = prefix + input + postfix

    iv = new_iv()
    return iv, aes_cbc_encrypt(profile, key, iv)

def decrypt_profile(ct, iv):
    """
    Decrypt a given profile
    """
    pt = aes_cbc_decrypt(ct, key, iv)

    print("Plaintext:", pt)

    profile = parse_kv(pt)
    print("Profile:", profile)

    return profile.get(b"admin") == b"true"


def bitflip_attack():
    """
    Encrypt a chosen message and flip a bit to
    change the result of the byte at the same position
    in the next block.

    As we cannot use:
    ';' = 0x3b = 0b0011 1011
    '=' = 0x3d = 0b0011 1101

    We use the following chars that are only one bit off:
    ':' = 0x3a = 0b0011 1010 for ';'
    '<' = 0x3c = 0b0011 1100 for '='
    """

    # We need our username to be on the block before the payload:
    # Bloc 0: comment1=cooking
    # Bloc 1: %20MCs;userdata=
    # Bloc 2: aaaaaaaaaaaaaaaa ('a' = 0x61 = 0b0110 0001)
    # Bloc 3: :admin< true;com
    # Rest of the message

    message = b"a" * 16 + b":admin<true"
    iv, profile = profile_for(message)

    profile = bytearray(profile)
    temp = profile

    # Now flip LSB of bytes 0 and 6 of bloc 3
    # to change ';' into ':' and '<' into '='
    profile[32] ^= 0x01
    profile[38] ^= 0x01

    is_admin = decrypt_profile(profile, iv)

    if is_admin:
        print("Successfully forged an admin profile")


if __name__ == "__main__":
    bitflip_attack()