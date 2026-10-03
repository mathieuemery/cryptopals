# Bleichenbacher's e=3 RSA Attack

from sympy import integer_nthroot
from primitives.rsa import keygen
from primitives.sha1 import SHA1

e = 3

# Reference: https://crypto.stackexchange.com/questions/30183/how-do-you-communicate-the-hash-function-used-with-rsa-signing
ASN1_SHA1 = bytes.fromhex(
    "3021300906052b0e03021a05000414"
)

def verify_forged_signature(s, n, m):
    """
    Vulnerable RSA signature verification.

    Only checks that the decoded signature starts
    with the expected PKCS#1 v1.5 prefix.
    """
    k = (n.bit_length() + 7) // 8

    block = pow(s, e, n)
    block = block.to_bytes(k, "big")

    expected = (
        b"\x00\x01\xff\x00"
        + ASN1_SHA1
        + SHA1(m).hexbytes()
    )

    return block.startswith(expected)

def forge_signature(n):
    """
    Create a signature whose RSA result starts with
    the expected prefix. Since e=3, we can use a
    cube root to find the forged signature.
    """
    k = (n.bit_length() + 7) // 8

    digest = SHA1(m)

    # The vulnerable verifier only checks this prefix
    prefix = (
        b"\x00\x01\xff\x00"
        + ASN1_SHA1
        + digest.hexbytes()
    )

    # Put the prefix in the most significant bytes and
    # leave the unchecked bytes as zero
    prefix_int = int.from_bytes(prefix, "big")
    garbage_bytes = k - len(prefix)
    target = prefix_int << (8 * garbage_bytes)

    # Find the smallest s such that s^3 >= target
    s, exact = integer_nthroot(target, 3)

    if not exact:
        s += 1

    return s


if __name__ == "__main__":
    m = b'hi mom'
    n, d = keygen(e)
    
    s = forge_signature(n)

    print("forged signature:", s)

    if verify_forged_signature(s, n, m):
        print("Signature is valid")