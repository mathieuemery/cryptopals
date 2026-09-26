# CTR bitflipping

from primitives.aes_ctr import aes_ctr_decrypt, aes_ctr_encrypt

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

    return aes_ctr_encrypt(profile, key)


def decrypt_profile(ct, iv):
    """
    Decrypt a given profile
    """
    pt = aes_ctr_decrypt(ct, key, iv)

    print("Plaintext:", pt)

    profile = parse_kv(pt)
    print("Profile:", profile)

    return profile.get(b"admin") == b"true"


def bitflip_attack():
    """
    Similar to the attack on CBC but much easier
    as the flip is done directly on the byte we want
    to change instead of the one in the previous block.

    We cannot use the following values:
    ';' = 0x3b = 0b0011 1011
    '=' = 0x3d = 0b0011 1101

    But we can use these that are only one
    bit off and then flip it:
    ':' = 0x3a = 0b0011 1010 for ';'
    '<' = 0x3c = 0b0011 1100 for '='

    We create the following token
    Bloc 0: comment1=cooking
    Bloc 1: %20MCs;userdata=
    Bloc 2: :admin<true;comm
    Rest of the message
    """

    message = b":admin<true"
    iv, profile = profile_for(message)

    profile = bytearray(profile)
    temp = profile

    # Now flip LSB of bytes 0 and 6 of bloc 3
    profile[32] ^= 0x01
    profile[38] ^= 0x01

    is_admin = decrypt_profile(profile, iv)

    if is_admin:
        print("Forged an admin profile")


if __name__ == "__main__":
    bitflip_attack()