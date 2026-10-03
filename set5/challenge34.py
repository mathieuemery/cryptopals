# Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
from primitives.dh import derive_key, key_gen
from primitives.aes_cbc import aes_cbc_decrypt, aes_cbc_encrypt, new_iv

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2

def message_a(s):
    """
    Create the message from A.
    """
    msg = b'Hello !'

    iv = new_iv()
    ct = aes_cbc_encrypt(msg, s, iv)

    print('A encrypts message for "B"')

    return ct, iv


def message_m(s_ma, s_mb, ct_a, iv):
    """
    Retrieve message from A and re-encrypt for B.
    """
    pt = aes_cbc_decrypt(ct_a, s_ma, iv)
    print("M received a message from A: ", pt)

    iv = new_iv()
    ct = aes_cbc_encrypt(pt, s_mb, iv)

    print("M re-encrypted message for B")

    return ct, iv

def message_b(s, ct_m, iv):
    """
    Decrypt message from the MitM attacker and
    re-encrypt it.
    """
    pt = aes_cbc_decrypt(ct_m, s, iv)
    print('B received a message from "A": ', pt)

    iv = new_iv()
    ct = aes_cbc_encrypt(pt, s, iv)

    return ct, iv


def mitm_attack():
    """
    Simulate a MitM attack where M intercepts
    message from A and B.
    """
    # Generate A's keys and M's keys for A
    a, A = key_gen(g, p)
    m_a, M_a = key_gen(g, p)

    # Generate B's keys and M's keys for B
    b, B = key_gen(g, p)
    m_b, M_b = key_gen(g, p)

    # Derive the shared secret for A-M and M-B
    s_a = derive_key(a, M_a, g, p)
    s_ma = derive_key(m_a, A, g, p)
    s_b = derive_key(b, M_b, g, p)
    s_mb = derive_key(m_b, B, g, p)

    assert s_a == s_ma
    assert s_b == s_mb

    # MitM attack where M intercepts the messages
    # between A and B
    ct_a, iv_a = message_a(s_a)
    ct_m, iv_m = message_m(s_ma, s_mb, ct_a, iv_a)
    ct_b, iv_b = message_b(s_b, ct_m, iv_m)


if __name__ == "__main__":
    mitm_attack()