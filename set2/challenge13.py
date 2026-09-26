# ECB cut-and-paste

from primitives.aes import BLOCK_LEN
from primitives.aes_ecb import aes_ecb_encrypt, aes_ecb_decrypt
from primitives.pkcs7 import pkcs7_padding

key = b"YELLOW SUBMARINE"

def parse_kv(s):
    """
    Parses the cookie to get the key-value
    pairs.
    """
    profile = {}

    for pair in s.split("&"):
        key, value = pair.split("=", 1)
        profile[key] = value

    return profile

def profile_for(email):
    """
    Create a cookie for a given email
    """
    email = email.replace(b"&", b"").replace(b"=", b"")

    profile = b"email=" + email + b"&uid=10&role=user"

    return aes_ecb_encrypt(profile, key)


def decrypt_profile(ct):
    """
    Decrypt a given profile
    """
    pt = aes_ecb_decrypt(ct, key)
    print("Plaintext:", pt)

    profile = parse_kv(pt.decode())
    print("\nProfile:", profile)

    return profile


def forge_admin_token():
    """
    This attack works by encrypting blocks with
    AES in ECB mode (which is deterministic for the
    same input) and then rearrange them so they get
    decrypted as the plaintext we want
    """

    # This gives us the following blocks:
    # pt1_0 = email=aaaaaaaaaa
    # pt2_0 = aaa&uid=10&role=
    pt1 = b"a" * 13
    ct1 = profile_for(pt1)

    # Create a second ciphertext where the second
    # block is the expected plaintext for our attack
    # to work:
    # pt1_1 = email=aaaaaaaaaa
    # pt2_1 = admin<pad>
    padded = pkcs7_padding(b"admin", BLOCK_LEN)
    pt2 = b"a" * 10 + padded
    ct2 = profile_for(pt2)

    # Now use pt1_0, pt2_0 and pt2_1 so when
    # the message is decrypted we get pt1_0
    # + pt2_0 + pt_2_1 which is decrypted as:
    # pt1 = email=aaaaaaaaaa
    # pt2 = aaa&uid=10&role=
    # pt3 = admin<pad>
    #
    # and it then parsed as:
    # email=aaaaaaaaaaaaa&uid=10&role=admin<pad>

    final_ct = ct1[:32] + ct2[16:32]
    return final_ct
    

if __name__ == "__main__":
    token = forge_admin_token()

    decrypt_profile(token)