from primitives.sha1 import SHA1
import secrets

# https://rosettacode.org/wiki/Modular_exponentiation#Python
def power_mod(b, e, m):
    """
    Compute the power mod without using built-in functions.
    """
    x = 1
    while e > 0:
        b, e, x = (
            b * b % m,
            e // 2,
            b * x % m if e % 2 else x
        )

    return x


def key_gen(g, p):
    """
    Generate a DH private and public key.
    """
    priv = secrets.randbelow(p)
    pub = power_mod(g, priv, p)

    return priv, pub


def derive_key(sk, remote_pk, g, p):
    """
    Derive a shared secret from the DH handshake.
    """
    s = power_mod(remote_pk, sk, p)

    s_bytes = s.to_bytes((s.bit_length() + 7) // 8, byteorder="big")
    key = SHA1(s_bytes).bytes()

    return key[:16]