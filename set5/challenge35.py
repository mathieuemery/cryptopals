# Implement DH with negotiated groups, and break with malicious "g" parameters
from primitives.dh import derive_key, key_gen
from primitives.aes_cbc import aes_cbc_decrypt, aes_cbc_encrypt, new_iv
from primitives.sha1 import SHA1

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

def message_a(s, msg):
    """
    Create the message from A.
    """
    iv = new_iv()
    ct = aes_cbc_encrypt(msg, s, iv)

    return ct, iv


def message_b(s, ct_m, iv):
    """
    Decrypt message from A and re-encrypt it.
    """
    pt = aes_cbc_decrypt(ct_m, s, iv)

    return pt


def g_equal_one():
    """
    In this case, the keygen gives:
    A = 1^a mod p = 1, the same for B
    
    It means we have A = B and that A^b gives
    also 1. The key is then the first 16 bytes
    of the sha1 hash of \x01.
    """
    g = 1
    msg = b'Hello !'

    a, A = key_gen(g, p)
    b, B = key_gen(g, p)

    s_a = derive_key(a, B, g, p)
    s_b = derive_key(b, A, g, p)

    assert s_a == s_b

    # Forge a key
    forged_key = SHA1(b'\x01').bytes()[:16]

    assert s_a == forged_key

    ct_a, iv_a = message_a(s_a, msg)
    pt = message_b(forged_key, ct_a, iv_a)

    if pt == msg:
        print("Succesfully exploited g = 1")


def g_equal_p():
    """
    Here keygen gives:
    A = p^a mod p which can be simplified to:
    A = (p mod p)^a mod p = 0 (same for B)

    Once again A = B = 0 which means the shared
    key = hash(0^a mod p) = hash(0)
    """
    g = p
    msg = b'Hello !'

    a, A = key_gen(g, p)
    b, B = key_gen(g, p)

    s_a = derive_key(a, B, g, p)
    s_b = derive_key(b, A, g, p)

    assert s_a == s_b

    # Forge a key
    forged_key = SHA1(b'').bytes()[:16]

    assert s_a == forged_key

    ct_a, iv_a = message_a(s_a, msg)
    pt = message_b(s_b, ct_a, iv_a)

    if pt == msg:
        print("Succesfully exploited g = p")


def g_equal_p_minus_one():
    """
    For g = p-1, the keygen is:
    A = (p-1)^a mod p

    (p-1)^a mod p can be simplified as (-1)^a mod p.
    The result is then "-1" if `a` is odd and "1" if
    it is even.
    """
    g = p-1
    msg = b'Hello !'

    a, A = key_gen(g, p)
    b, B = key_gen(g, p)

    s_a = derive_key(a, B, g, p)
    s_b = derive_key(b, A, g, p)

    assert s_a == s_b

    # The only possible shared secrets are 1 and p-1.
    possible_secrets = [1, p - 1]

    forged_key = None
    for s in possible_secrets:
        s_bytes = s.to_bytes(
            (s.bit_length() + 7) // 8,
            byteorder="big"
        )
        key = SHA1(s_bytes).bytes()[:16]

        if key == s_a:
            forged_key = key
            break

    assert forged_key is not None

    ct_a, iv_a = message_a(s_a, msg)
    pt = message_b(forged_key, ct_a, iv_a)

    if pt == msg:
        print("Succesfully exploited g = p-1")


if __name__ == "__main__":
    g_equal_one()
    g_equal_p()
    g_equal_p_minus_one()