import secrets
import hashlib


def generate_keypair(base, order):
    """
    Derive a new keypair for ECDH.
    """
    secret = secrets.randbelow(order - 1) + 1
    public = base.scale(secret)
    return (secret, public)


def point_to_key(point):
    """
    Convert an elliptic point to a key.
    """
    if point.is_infinity:
        x_bytes = b""
    else:
        x = point.x
        x_bytes = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    return hashlib.sha1(x_bytes).digest()[:16]


def derive_key(sk, remote_pk):
    """
    Derive a shared secret from the DH handshake.
    """
    return point_to_key(remote_pk.scale(sk))