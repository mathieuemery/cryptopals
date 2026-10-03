import secrets
from hashlib import sha256

p = int(
    "800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65e"
    "ac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc5"
    "65f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232"
    "c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1",
    16,
)

q = int("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)

g = int(
    "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4"
    "046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e02"
    "5e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c8"
    "87892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291",
    16,
)

def keygen():
    """
    Generate a keypair for DSA.
    """
    a = secrets.randbelow(q-1) + 1 # So 0 is never chosen
    A = pow(g, a, p)

    return a, A


def sign(m, a, k: int | None = None, hash: int | None = None):
    """
    Signs a message. Allows to give the `k` as some challenges
    require it (not great).
    """
    if k is None:
        k = secrets.randbelow(q - 1) + 1
    r = pow(g, k, p) % q

    inv_k = pow(k, -1, q)

    if hash is None:
        hash = int.from_bytes(sha256(m).digest(), 'big')
    s = ((hash + a * r) * inv_k) % q

    return r, s


def verify(m, r, s, A):
    """
    Verify a DSA signature.
    """
    assert r != 0 and s != 0

    inv_s = pow(s, -1, q)

    hash = int.from_bytes(sha256(m).digest(), 'big')
    r_1 = ((pow(g, hash * inv_s, p) * pow(A, r*inv_s, p)) % p) % q

    return r == r_1