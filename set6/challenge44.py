# DSA nonce recovery from repeated nonce

from primitives.dsa import q
from collections import defaultdict
from hashlib import sha1

y = int(
    "2d026f4bf30195ede3a088da85e398ef869611d0f68f07"
    "13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8"
    "5519b1c23cc3ecdc6062650462e3063bd179c2a6581519"
    "f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430"
    "f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3"
    "2971c3de5084cce04a2e147821",
    16
)

expected_sk_hash = "ca8f6f7c66fa362d40760d135b763eb8527d3d52"

def get_values(path):
    """
    Recover s, r, m and msg from the file.
    """
    records = []

    with open(path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    for i in range(0, len(lines), 4):
        records.append({
            "msg": lines[i].removeprefix("msg: "),
            "s": int(lines[i + 1].removeprefix("s: ")),
            "r": int(lines[i + 2].removeprefix("r: ")),
            "m": int(lines[i + 3].removeprefix("m: "), 16),
        })

    return records

def find_k_reuse(records):
    """
    Find signatures where the nonce was reused.

    Easy as the r values would be the same for
    different messages.
    """
    current = {}

    # Group records by r
    by_r = defaultdict(list)

    for record in records:
        by_r[record["r"]].append({
            "m": record["m"],
            "s": record["s"]
        })

    # Keep only reused r values
    return {
        r: entries
        for r, entries in by_r.items()
        if len(entries) > 1
    }


def find_k(m0, m1, s0, s1):
    """
    From two messages and their signatures (that
    used the same nonce), find back the nonce.
    """
    m_dif = (m0 - m1) % q
    s_dif = (s0 - s1) % q
    k = (m_dif * pow(s_dif, -1, q)) % q
    return k


def recover_sk(s, k, H_m, r):
    """
    From r, s, the `k` nonce and the message's hash,
    recover the private key.
    """
    inv_r = pow(r, -1, q)
    return (((s * k) - H_m) * inv_r) % q


def sk_from_k_reuse():
    """
    Parses the file, identifies the reused nonce,
    then find the nonce and the private key.
    """
    records = get_values("data/44.txt")

    reused = find_k_reuse(records)

    for r, entries in reused.items():
        m0 = entries[0]['m']
        s0 = entries[0]['s']
        m1 = entries[1]['m']
        s1 = entries[1]['s']

        k = find_k(m0, m1, s0, s1)
        print(f"r = {r}")
        print(f"k = {k}\n")

        private_key = recover_sk(s0, k, m0, r)

        sk_str = f"{private_key:x}"
        sk_hash = sha1(sk_str.encode("ascii")).hexdigest()

        if sha1(sk_str.encode("ascii")).hexdigest() == expected_sk_hash:
            print("Found the private key: ", private_key)
            break


if __name__ == "__main__":
    sk_from_k_reuse()