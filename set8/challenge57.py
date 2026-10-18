# Diffie-Hellman Revisited: Subgroup-Confinement Attacks

from primitives.dh import key_gen, derive_key
from random import randrange
import hmac, hashlib

p = 7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771
g = 4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143
q = 236234353446506858198510045061214171961

j = 30477252323177606811760882179058908038824640750610513771646768011063128035873508507547741559514324673960576895059570
# Used sagemath to factor `j`
factors = [2, 3, 5, 109, 7963, 8539, 20641, 38833, 39341, 46337, 51977, 54319, 57529, 96142199, 46323892554437, 534232641372537546151, 80913087354323463709999234471]


def compute_h(r):
    """
    Compute h = rand(1, p)^((p-1)/r) mod p.

    Restart if h = 1
    """
    while True:
        h = pow(randrange(1, p), int((p-1)//r), p)
        if h != 1:
            return h


def compute_mac(h, m):
    """
    Compute the secret as if `h` was a 
    valid public key.
    
    Then compute the MAC of the message
    using this key.
    """
    secret = derive_key(a, h, g, p)

    t = hmac.new(secret, m, hashlib.sha256).digest()
    
    return m, t


def find_x(r, h, m, t):
    """
    Find the correct key for this `h` and the
    current factor `r`.
    """
    for i in range(r):
        k = derive_key(i, h, g, p)
        mac = hmac.new(k, m, hashlib.sha256).digest()

        if mac == t:
            print("Found the x:", i)
            return i


def crt(residues):
    """
    Compute the Chinese Remainder Theorem on
    a bunch of residues.
    """
    N = 1
    for n, _ in residues:
        N *= n

    result = 0
    for n, c in residues:
        M = N // n
        result += c * M * pow(M, -1, n)

    return result % N


def find_key(m):
    """
    Find the private key of Bob.
    """
    residues = []

    for r in factors[:12]:
        h = compute_h(r)
        m, t = compute_mac(h, m)
        x = find_x(r, h, m, t)

        print(f"r={r}, recovered={x}, expected={a % r}")
        residues.append((r, x))

    recovered = crt(residues)
    assert recovered == a % q

    print("Recovered the correct key:", recovered)



if __name__ == "__main__":
    m = b'crazy flamboyant for the rap enjoyment'

    # Generate Bob's keys
    a, A = key_gen(g, q)

    find_key(m)
