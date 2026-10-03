# Implement an E=3 RSA Broadcast attack
from primitives.rsa import keygen, encrypt
from sympy import integer_nthroot

e = 3
m = int.from_bytes(b'my secret message')

def encrypt_message(m):
    """
    Generate new RSA keys and encrypt
    the message with them.
    """
    n, d = keygen(e)

    c = encrypt(m, e, n)

    return n, c

# Reference: https://en.wikipedia.org/wiki/Chinese_remainder_theorem
def crt(n_0, c_0, n_1, c_1, n_2, c_2):
    """
    Use the Chinese Remainder Theorem to recover the value C
    modulo N = n_0 * n_1 * n_2 such that:
        C ≡ c_0 (mod n_0)
        C ≡ c_1 (mod n_1)
        C ≡ c_2 (mod n_2)
    """
    m_s_0 = n_1 * n_2
    m_s_1 = n_0 * n_2
    m_s_2 = n_0 * n_1

    n_012 = n_0 * n_1 * n_2

    return ((c_0 * m_s_0 * pow(m_s_0, -1, n_0)) + (c_1 * m_s_1 * pow(m_s_1, -1, n_1)) + (c_2 * m_s_2 * pow(m_s_2, -1, n_2))) % n_012


def broadcast_attack():
    """
    Encrypt three times the same message with three
    different RSA modulus and `e` = 3. Each ciphertext
    is c_i = m^3 mod n_i.

    CRT allows to compute: C ≡ m^3 (mod n_0 * n_1 * n_2).

    If m^3 < n_0 * n_1 * n_2, the result of CRT allows
    to recover the plaintext by computing the exact
    integer cube root.
    """
    n_0, c_0 = encrypt_message(m)
    n_1, c_1 = encrypt_message(m)
    n_2, c_2 = encrypt_message(m)

    c = crt(n_0, c_0, n_1, c_1, n_2, c_2)
    
    m1, exact = integer_nthroot(c, 3)

    assert exact
    return m1


if __name__ == "__main__":
    recovered = broadcast_attack()
    print(recovered.to_bytes((recovered.bit_length() + 7) // 8, "big"))