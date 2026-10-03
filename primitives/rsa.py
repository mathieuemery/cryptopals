from sympy import randprime
from math import gcd

def keygen(e):
    """
    Generate private and public keys
    """
    while True:
        p = randprime(2**1023, 2**1024)
        q = randprime(2**1023, 2**1024)

        phi_n = (p - 1) * (q - 1)

        if gcd(e, phi_n) == 1:
            break

    n = p * q
    d = pow(e, -1, phi_n)

    return n, d


def encrypt(m, e, n):
    """
    Encrypt a message with textbook RSA.
    """
    c = pow(m, e, n)
    return c


def decrypt(c, d, n):
    """
    Decrypt a message with textbook RSA.
    """
    m = pow(c, d, n)
    return m