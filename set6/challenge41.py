# Implement unpadded message recovery oracle

from primitives.rsa import keygen, encrypt, decrypt
import random

m = int.from_bytes(b'my secret message')
e = 65537

def verify_message(c1, d, n, decrypted_ciphertext):
    """
    Decrypt the ciphertext only if it was not
    previously decrypted.
    """
    if c1 == decrypted_ciphertext:
        raise ValueError("Ciphertext already decrypted")

    return decrypt(c1, d, n)


def unpadded_message_attack(c, e, n):
    """
    Compute C' = ((S**E mod N) C) mod N with
    S a random number > 1 mod N.
    """
    s = random.randint(2, 10)

    return (pow(s, e, n) * c) % n, s


def recover_message():
    """
    Encrypt a message and then only decrypt another
    if it is a different one to recover the message.

    For textbook RSA, if c = m^e mod n, then decrypting c'
    gives: (s^e * c)^d mod n = (s^e * m^e)^d mod n
    = s * m mod n.

    We can then find back the message by multiplying
    the result by s^(-1) mod n.
    """
    n, d = keygen(e)
    c = encrypt(m, e, n)

    c1, s = unpadded_message_attack(c, e, n)

    p_1 = verify_message(c1, d, n, c)

    s_inv = pow(s, -1, n)
    p = (p_1 * s_inv) % n

    print(p.to_bytes((p.bit_length() + 7) // 8, "big"))


if __name__ == "__main__":
    recover_message()