# Recover the key from CBC with IV=Key

from primitives.aes_cbc import aes_cbc_decrypt, aes_cbc_encrypt, fixed_xor

prefix = b"comment1=cooking%20MCs;userdata="
postfix = b";comment2=%20like%20a%20pound%20of%20bacon"

key = b"YELLOW SUBMARINE"
iv = key

def validate_ascii(pt):
    """
    Validate a plaintext only contains ascii
    characters.
    """
    for byte in pt:
        if byte >= 128:
            raise Exception("Non-ASCII plaintext:", pt)

def profile_for(input):
    """
    Create a cookie for a given email
    """
    input = input.replace(b";", b"").replace(b"=", b"")

    profile = prefix + input + postfix

    return aes_cbc_encrypt(profile, key, iv)

def decrypt_profile(profile, key, iv):
    """
    Decrypt a given profile
    """
    pt = aes_cbc_decrypt(profile, key, iv)
    validate_ascii(pt)


def find_key():
    """
    The idea is encrypting message that is at least
    three blocs long to get: CT0 || CT1 || CT2

    We then forge the ciphertext so it looks like this:
    CT0 || '0' * 16 || CT0

    When decrypted in CBC mode, this will return:
    PT0 xor IV || ... || PT0

    We can then find back the IV (the key) by xoring
    the decrypted blocks 0 and 2.
    """
    input = b"A" * 64 + b"\xff"

    profile = bytearray(profile_for(input))

    # Edit profile to have CT0, 0, CT0
    profile[16:32] = b"\x00" * 16
    profile[32:48] = profile[:16]

    try:
        decrypt_profile(profile, key, iv)
    except Exception as e:
        bad_pt = e.args[1]
        
        # Here we have PT0 xor IV || ... || PT0
        # and can find back the key
        found_key = fixed_xor(bad_pt[:16], bad_pt[32:48])
        return found_key

if __name__ == "__main__":
    found_key = find_key()
    
    if found_key == key:
        print("Found the key:", found_key)