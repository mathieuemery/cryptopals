# Create the MT19937 stream cipher and break it

from primitives.mt19937 import mt19937
from utils.xor import xor
import secrets
import time

prefix_length = secrets.randbelow(100)
random_prefix = secrets.token_bytes(prefix_length)

def keystream(prng, n):
    """
    Generate a keystream from the prng
    """
    stream = bytearray()

    while len(stream) < n:
        value = prng.random_uint32()

        stream.extend(value.to_bytes(4, "big"))

    return stream[:n]


def encrypt(pt, seed):
    """
    Encrypt a message using MT19937
    as a stream cipher
    """
    prng = mt19937(seed)
    key = keystream(prng, len(pt))

    return xor(pt, key)


def decrypt(ct, seed):
    """
    Decrypt a message using MT19937
    as a stream cipher
    """
    prng = mt19937(seed)
    key = keystream(prng, len(ct))

    return xor(ct, key)


def validate_impl():
    pt = b"Very secret message"
    seed = 12312

    ct = encrypt(pt, 12312)
    recovered_pt = decrypt(ct, 12312)

    if pt == recovered_pt:
        print("The mt19937 stream cipher is working")
    else:
        print(f"Implementation error, expected {pt}, got {recovered_pt}")


def break_mt19937():
    """
    As the seed is only 16-bit long, we can bruteforce
    all possibilities
    """
    random_seed = secrets.randbits(16)

    pt = random_prefix + b'A' * 14

    ct = encrypt(pt, random_seed)

    for i in range(2**16):
        test_pt = decrypt(ct, i)
        if test_pt.endswith(b'A' * 14):
            break

    if random_seed == i:
        print("Found the seed:", i)


def generate_token():
    """
    Generate a password reset token
    """
    seed = int(time.time())
    prng = mt19937(seed)

    return keystream(prng, 16)


def is_mt19937_time_seeded(token):
    """
    Check if a password token was created
    using MT19937 seeded with the current
    time.

    Bruteforce the seed by testing all the
    timestamps from the last 5 minutes
    """
    now = int(time.time())

    for seed in range(now - 5 * 60, now + 1):
        prng = mt19937(seed)
        candidate = keystream(prng, len(token))

        if candidate == token:
            return True

    return False


if __name__ == "__main__":
    validate_impl()

    break_mt19937()

    token = generate_token()
    assert is_mt19937_time_seeded(token)

    not_seeded = secrets.token_bytes(16)
    assert not is_mt19937_time_seeded(not_seeded)

    print("Time seeded mt19937 detector is working")