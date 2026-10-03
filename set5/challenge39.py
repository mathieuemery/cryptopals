# Implement RSA
from primitives.rsa import keygen, encrypt, decrypt

e = 3

def validate():
    n, d = keygen(e)
    m1 = 42

    c = encrypt(m1, e, n)
    m2 = decrypt(c, d, n)
    
    if m1 == m2:
        print("Round-trip OK")


if __name__ == "__main__":
    validate()
    