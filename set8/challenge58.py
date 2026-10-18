# Pollard's Method for Catching Kangaroos
# Reference: https://en.wikipedia.org/wiki/Pollard's_kangaroo_algorithm

from primitives.dh import derive_key, power_mod
from sympy.ntheory.modular import crt
from math import ceil, log2, sqrt, prod
from random import randrange
import hmac, hashlib
import secrets


p = 11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623
q = 335062023296420808191071248367701059461
j = 34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702
# Factored with sage:
# j = 2 * 12457 * 14741 * 18061 * 31193 * 33941 * 63803 * 76404216680248147890725465466734243970853371218438495046025185507551527833728478710665337

g = 622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357

y1 = 7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119
y2 = 9388897478013399550694114614498790691034187453089355259602614074132918843899833277397448144245883225611726912025846772975325932794909655215329941809013733


def key_gen(g, p, q):
    """
    DH key generation that allows passing
    both `p` and `q`.
    """
    priv = secrets.randbelow(q)
    pub = power_mod(g, priv, p)
    return priv, pub


def f(y, k):
    """
    Generate sequences by mapping group
    elements to scalars.
    """
    return 2 ** (y % k)


def tame_kangaroo(g, b, N, k, p):
    """
    Generate the control sequence (the tame kangaroo).
    """
    xT = 0
    yT = pow(g, b, p)
    tame_points = {yT: xT}

    for _ in range(N):
        jump = f(yT, k)
        xT += jump
        yT = (yT * pow(g, jump, p)) % p
        tame_points.setdefault(yT, xT)

    return tame_points, xT


def wild_kangaroo(g, y, a, b, tame_points, max_tame_distance, k, p):
    """
    Generate the wild kangaroo sequence and look
    for a collision with our controled sequence.
    """
    xW = 0
    yW = y
    max_distance = (b - a) + max_tame_distance

    while xW <= max_distance:
        if yW in tame_points:
            xT = tame_points[yW]
            candidate = b + xT - xW

            if a <= candidate <= b and pow(g, candidate, p) == y:
                return candidate

        jump = f(yW, k)
        xW += jump
        yW = (yW * pow(g, jump, p)) % p

    return None


def verify(g, x, p, y, upper_bound):
    """
    Verify the `x` value we found gives
    the correct `y`.
    """
    assert 0 <= x <= upper_bound

    if pow(g, x, p) == y:
        print("Found the correct value for x")
    else:
        print(f'Expected g^x mod p = {y}, got {pow(g,x,p)}')


def find_x2(g_base, a, b, k, y, N):
    """
    Finds `x` for y = g^x mod p by finding a collision
    between a controlled sequence and a wild kangaroo.

    We don't know where the wild kangaroo starts but we
    can know how many steps it did before the collision
    happened.

    If the tame kangaroo starts at g^b, then travels a
    total distance `dt`, its position is y_t = g^(b+dt) mod p.

    If the wild kangaroo started at y = g^x, then after
    travelling a distance `dw` its position is
    y_w = g^(x+dw) mod p.

    When the two positions collide, y_t = y_w so:
    g^(b+dt) = g^(x + dw) mod p.

    We can compute x = b + dt - dw.
    """
    tame_points, max_tame_distance = tame_kangaroo(g_base, b, N, k, p)

    print("Tame points:", len(tame_points))
    print("Tame distance:", max_tame_distance)

    x1 = wild_kangaroo(
        g_base, y, a, b, tame_points, max_tame_distance, k, p
    )

    print("x1 =", x1)

    if x1 is None:
        print("No collision found")
        return None

    verify(g_base, x1, p, y, b)
    return x1


def compute_h(r):
    """
    Compute h = rand(1, p)^((p-1)/r) mod p.

    Restart if h = 1
    """
    while True:
        h = pow(randrange(1, p), int((p-1)//r), p)
        if h != 1:
            return h


def compute_mac(a, h, m):
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


def find_residues(factors, a):
    """
    Recover a mod r for each small factor r via subgroup
    confinement.
    """
    residues = []
    m = b'Random message'

    for r in factors[:12]:
        h = compute_h(r)
        m, t = compute_mac(a, h, m)
        x = find_x(r, h, m, t)

        print(f"r={r}, recovered={x}, expected={a % r}")
        residues.append((r, x))
    
    return residues


def kangaroo_params(a, b):
    """
    Return (k, N): jump-set size and tame-walk length for
    interval [a, b].
    """
    width = b - a

    k = ceil(
        log2(sqrt(width))
        + log2(log2(sqrt(width)))
        - 2
    )

    mean_jump = (2**k - 1) / k

    # This is the heuristic from your successful run.
    N = ceil(4 * mean_jump)

    return k, N


def find_private_key(x, y):
    """
    Recover the private key from y: CRT for x mod R,
    then kangaroo for the rest.
    """
    small_factors = [2, 12457, 14741, 18061, 31193, 33941, 63803]
    residues = find_residues(small_factors, x)
    R = prod(r for r, _ in residues)
    n, _ = crt(
        [r for r, _ in residues],
        [v for _, v in residues]
    )
    n = int(n)

    print("R =", R)
    print("n =", n)

    g_prime = pow(g, R, p)
    y_prime = (y * pow(pow(g, n, p), -1, p)) % p

    m_max = (q - 1 - n) // R

    print("m_max =", m_max)

    k, N = kangaroo_params(0, m_max)
    m = find_x2(g_prime, 0, m_max, k, y_prime, N)

    if m is None:
        raise ValueError("Kangaroo failed to recover m")

    x_recovered = n + m * R

    assert 0 <= x_recovered < q
    assert pow(g, x_recovered, p) == y

    if x_recovered == x:
        print("Found the private key !")


if __name__ == "__main__":
    # Part 1: Find x for y1 
    print("Finding x1:")
    k = 10
    N = 10000
    a = 0
    b = 2**20
    find_x2(g, a, b, k, y1, N)

    # Part 2: Find x for y2
    print("\nFinding x2:")
    k = 22
    a = 0
    b = 2**40
    mean_jump = (2**k - 1) / k
    N = ceil(4 * mean_jump)
    find_x2(g, a, b, k, y2, N)

    # Part 3: Find Bob's key
    print("\nFinding Bob's key:")

    # Generate Bob's key
    x, y = key_gen(g, p, q)
    print("Target private key:", x)
    find_private_key(x, y)