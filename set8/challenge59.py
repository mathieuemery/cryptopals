# Elliptic Curve Diffie-Hellman and Invalid-Curve Attacks

from primitives.ecdh import derive_key, generate_keypair, point_to_key
from primitives.ec import EllipticCurve
from random import randrange
import hmac, hashlib
import itertools

p = 233970423115425145524320034830162017933
curve = EllipticCurve(p, -95051, 11279326)
G = curve.point(182, 85518893674295321206118380980485522083)
q = 29246302889428143187362802287225875743 # order of G

# Known weak curves, their orders and factorizations
CURVES = [
    (EllipticCurve(p, -95051, 210),
     233970423115425145550826547352470124412,
     [2, 3, 11, 23, 31, 89, 4999, 28411, 45361, 109138087, 39726369581]),
    (EllipticCurve(p, -95051, 504),
     233970423115425145544350131142039591210,
     [2, 5, 7, 11, 61, 12157, 34693, 11810604523200031240395593]),
    (EllipticCurve(p, -95051, 727),
     233970423115425145545378039958152057148,
     [2, 7, 23, 37, 67, 607, 1979, 13327, 13799, 663413139201923717]),
]


# Constant that fixes the max residue size
MAX_BRUTE_FORCE = 1 << 20


def validate():
    """
    Validate the ECDH implementation
    has the expected behaviour.
    """
    a_sk, a_pk = generate_keypair(G, q)
    b_sk, b_pk = generate_keypair(G, q)

    assert derive_key(a_sk, b_pk) == derive_key(b_sk, a_pk)
    assert G.scale(q).is_infinity

    print("Handshake OK.")


def mod_sqrt_5mod8(n, p):
    """
    Computes a square root of n modulo prime p when p ≡ 5 (mod 8).

    Uses modular exponentiation to construct a candidate root:
      v = (2n)^((p-5)/8) mod p
      i = 2n * v² mod p
      r = n * v * (i-1) mod p
    
    If n is a quadratic residue, the candidate satisfies r² ≡ n (mod p).
    Returns r if verified, or None if no square root exists.

    Reference: https://arxiv.org/pdf/2311.10956.
    """
    n %= p
    if n == 0:
        return 0
    
    # Compute `v` and `i`
    v = pow(2 * n, (p - 5) // 8, p)
    i = (2 * n * v * v) % p

    # Compute the root using n, v, and i
    r = (n * v * (i - 1)) % p
    if (r * r) % p != n:
        return None
    
    return r


def random_point(curve, max_try = 10):
    """
    Find a random point on `curve` by choosing
    a random x and solving for y.
    """
    p = curve.p
    for i in range(max_try):
        x = randrange(p)

        # Find the y^2 for this x and then compute the square root
        rhs = (x**3 + curve.a * x + curve.b) % p
        y = mod_sqrt_5mod8(rhs, p)
        if y is not None:
            return curve.point(x, y)

    raise ValueError("Couldn't find a y point")


def compute_h(curve, curve_order, r):
    """
    Create an invalid `h` point.

    Take a random Point and multiply it with
    the curve order divided by one of its residue.
    """
    attempt = 0
    while True:
        P = random_point(curve)

        h = P.scale(curve_order // r)
        if not h.is_infinity:
            return h

def compute_mac(bob_sk, m, h):
    """
    Compute the shared secret as if `h` were a valid public key,
    then MAC the message with it.
    """
    shared = h.scale(bob_sk)
    secret = point_to_key(shared)
    return hmac.new(secret, m, hashlib.sha256).digest()


def find_x(r, h, m, t):
    """
    Find the private key value for a given `h` and residue.

    Try all values between 1 and `r`.
    """
    candidate = h.curve.infinity()
    for i in range(r):
        secret = point_to_key(candidate)
        if hmac.new(secret, m, hashlib.sha256).digest() == t:
            print("Found the x:", i)
            return i
        candidate = candidate.add(h)
    return None


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


def find_key(bob_sk, m, bob_pk):
    """
    Recover Bob's private key using the invalid-curve attack.
    """
    # Only select valid residues (not too big or already selected)
    pool = {}
    for weak_curve, order, factors in CURVES:
        for r in factors:
            if r == 2 or r > MAX_BRUTE_FORCE or r in pool:
                continue
            pool[r] = (weak_curve, order)

    # Iterate over the residues and find the `x` for each one
    residues = []
    product = 1
    for r in sorted(pool):
        weak_curve, order = pool[r]
        h = compute_h(weak_curve, order, r)
        t = compute_mac(bob_sk, m, h)
        x = find_x(r, h, m, t)
        if x is None:
            continue

        print(f"r={r}, recovered={x}, expected={bob_sk % r}")
        residues.append((r, x))
        product *= r
        if product > q:
            break

    # As each residue is ambiguous: true value mod r is either x or r-x,
    # try every sign combination and check against Bob's real public key.
    options = [(r, [x, (r - x) % r]) for r, x in residues]
    for signs in itertools.product(*(vals for _, vals in options)):
        candidate_residues = list(zip((r for r, _ in options), signs))
        candidate = crt(candidate_residues)

        # Validate the private key against the known public key
        if G.scale(candidate) == bob_pk:
            print("Recovered private key:", candidate)
            return candidate

    raise ValueError("No sign combination matched Bob's public key")


if __name__ == "__main__":
    validate()

    m = b'crazy flamboyant for the rap enjoyment'

    bob_sk, bob_pk = generate_keypair(G, q)

    print("Target private key:", bob_sk, "\n")
    find_key(bob_sk, m, bob_pk)