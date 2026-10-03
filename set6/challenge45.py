# DSA parameter tampering

from primitives.dsa import keygen, sign, verify, p, q, g
import secrets
from hashlib import sha256

y = int(
    "2d026f4bf30195ede3a088da85e398ef869611d0f68f07"
    "13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8"
    "5519b1c23cc3ecdc6062650462e3063bd179c2a6581519"
    "f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430"
    "f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3"
    "2971c3de5084cce04a2e147821",
    16
)


def keygen(p, q, g):
    """
    Generates DSA keypair and allows to define
    the parameters.
    """
    a = secrets.randbelow(q-1) + 1 # So 0 is never chosen
    A = pow(g, a, p)

    return a, A


def sign(m, a, g):
    """
    Signs a message with DSA. Allows to
    choose a different `g` than the implemented
    primitive.
    """
    k = secrets.randbelow(q - 1) + 1
    r = pow(g, k, p) % q

    inv_k = pow(k, -1, q)

    hash = int.from_bytes(sha256(m).digest(), 'big')
    s = ((hash + a * r) * inv_k) % q

    return r, s


def verify(m, r, s, g, A):
    """
    Validate a DSA signature. Allows to
    choose a different `g` than the implemented
    primitive.
    """
    inv_s = pow(s, -1, q)

    hash = int.from_bytes(sha256(m).digest(), 'big')
    r_1 = ((pow(g, hash * inv_s, p) * pow(A, r*inv_s, p)) % p) % q

    return r == r_1


def g_equal_zero():
    """
    With g = 0, r is also 0. we then do 'a' * 0
    so the signature is only s = (hash/k) % q,
    the private key isn't used.

    When validating, any message passes (normally 
    it is needed to check if r and s are not 0)
    """
    g = 0
    a, A = keygen(p, q, g)

    m = b'Test message'

    r, s = sign(m, a, g)

    if verify(m, r, s, g, A):
        print("Signature for m is OK with g = 0")

    m2 = b'Test messae'

    if verify(m2, r, s, g, A):
        print("Signature for tampered m is OK with g = 0")


def g_equal_p_plus_one(y):
    """
    Since all DSA exponentiations are performed modulo p:
    g = p + 1 ≡ 1 (mod p).

    This makes the public key y = g^a mod p equal to 1 as well
    and the verification is independent of the message.
    """
    g = p + 1

    # Arbitrary value
    z = 12345

    r = pow(y, z, p) % q
    inv_z = pow(z, -1, q)

    s = (r * inv_z) % q
    
    m1 = b'Hello, world'
    if verify(m1, r, s, g, y):
        print("Signature is valid for m1 with g = p+1")

    m2 = b'Goodbye, world'
    if verify(m2, r, s, g, y):
        print("Signature is valid for m2 with g = p+1")


if __name__ == "__main__":
    g_equal_zero()
    g_equal_p_plus_one(y)