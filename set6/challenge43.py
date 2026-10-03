# DSA key recovery from nonce

from primitives.dsa import g, p, q
from hashlib import sha1

y = int(
    "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4b"
    "debf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788e"
    "fdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d2"
    "3eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99e"
    "a17",
    16,
)


def recover_sk(s, k, H_m, r):
    """
    From r, s, the `k` nonce and the message's hash,
    recover the private key.
    """
    inv_r = pow(r, -1, q)
    return (((s * k) - H_m) * inv_r) % q


def break_challenge():
    """
    Bruteforce the nonce so that we can find back the
    private key (only 2^16 possibilities).
    """
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940
    H_m = 0xD2D0714F014A9784047EAECCF956520045C45265 % q
    a_hash = "0954edd5e0afe5542a4adf012611a91912a3ec16"

    for k in range(1, 2**16):
        x = recover_sk(s, k, H_m, r)

        # Validate x directly against the public key y
        if pow(g, x, p) == y:
            x_hex_str = f"{x:x}"
            x_hash = sha1(x_hex_str.encode("ascii")).hexdigest()

            if x_hash == a_hash:
                print(f"Found matching nonce k: {k}")
                print(f"Private key x: {x}")
                return

    print("Private key not found.")


if __name__ == "__main__":
    break_challenge()