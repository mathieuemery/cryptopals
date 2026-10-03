# RSA parity oracle
# Got help from https://crypto.stackexchange.com/questions/11053/rsa-least-significant-bit-oracle-attack

from primitives.rsa import keygen, encrypt, decrypt
from fractions import Fraction
import base64

e = 65537
n, d = keygen(e)

def parity_oracle(c):
    """
    Returns `true` if the pt is odd
    """
    m = decrypt(c, d, n)

    return m % 2


def decrypt_with_oracle(c):
    """
    Recover the plaintext by narrowing its possible interval
    (originaly between 0 and N)

    Multiplying c by 2^e corresponds to multiplying the plaintext by 2
    modulo n. The parity of the result tells us which half of the
    current interval contains the plaintext.
    """
    lower = Fraction(0)
    upper = Fraction(n)

    c_i = c
    multiplier = pow(2, e, n)

    while upper - lower > 1:
        c_i = (multiplier * c_i) % n

        if parity_oracle(c_i):
            lower = (upper + lower) / 2
        else:
            upper = (upper + lower) / 2
        
    return int(lower), int(upper)


def validate_message(lower, upper, c):
    """
    Check which bound is the original plaintext.
    """
    if encrypt(lower, e, n) == c:
        print("Lower bound was the message.")
        return lower

    if encrypt(upper, e, n) == c:
        print("Upper bound was the message")
        return upper

    raise ValueError("Neither lower nor upper are valid")


def rsa_parity_attack():
    """
    Recover the plaintext using the parity oracle.
    """
    pt_64 = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
    m = int.from_bytes(base64.b64decode(pt_64))
    
    c = encrypt(m, e, n)
    lower, upper = decrypt_with_oracle(c)

    recovered = validate_message(lower, upper, c)

    m_1 = recovered.to_bytes(
        (recovered.bit_length() + 7) // 8,
        byteorder="big"
    )

    print("Found the message: ", m_1)


if __name__ == "__main__":
    rsa_parity_attack()