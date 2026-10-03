# Implement Diffie-Hellman
from primitives.dh import derive_key, key_gen

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2

def validate():
    """
    Validate we get a shared secret from the
    DH handshake.
    """
    a, A = key_gen(g, p)
    b, B = key_gen(g, p)

    s_1 = derive_key(a, B, g, p)
    s_2 = derive_key(b, A, g, p)

    assert s_1 == s_2

    print("Shared secret:", s_1.hex())

    print("Implementation is correct")

if __name__ == "__main__":
    validate()