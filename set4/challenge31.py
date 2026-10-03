import time
import urllib.request
import urllib.parse
import statistics
from primitives.hmac_sha1 import HMAC_SHA1

HOST = "localhost"
PORT = 9000
HMAC_LENGTH = 20
ATTEMPTS = 5

# Shared key with the server
key = b'YELLOW SUBMARINE'

FILE = b"temp.txt"

def request(file, signature):
    """
    Send a request to the server to check the signature
    of the file. Returns the time the response took to arrive.
    """
    signature_hex = signature.hex()

    params = urllib.parse.urlencode({
        "file": file,
        "signature": signature_hex,
    })

    url = f"http://localhost:9000/test?{params}"

    start = time.perf_counter()

    try:
        with urllib.request.urlopen(url) as response:
            response.read()

    except urllib.error.HTTPError as e:
        e.read()

    elapsed = time.perf_counter() - start

    return elapsed


def measure_candidate(candidate):
    """
    Do `ATTEMPTS` requests for each candidate to
    the server and return the median for each one
    of them.
    """
    timings = []

    for _ in range(ATTEMPTS):
        timings.append(request(FILE, candidate))

    return statistics.median(timings)


def find_byte(known_prefix):
    """
    Find the next byte of the valid MAC.
    """
    results = []

    for candidate in range(256):
        signature = known_prefix + bytes([candidate])

        # Fill the rest with zeroes
        signature += bytes(HMAC_LENGTH - len(signature))

        timing = measure_candidate(signature)

        results.append((timing, candidate))

    results.sort(reverse=True)

    best_timing, best_candidate = results[0]

    print(
        f"\n>>> Selected {best_candidate:02x} "
    )

    return bytes([best_candidate])

def find_valid_mac():
    """
    Find the valid MAC of a file.
    """
    recovered = b""

    for position in range(HMAC_LENGTH):
        print("=" * 60)
        print(f"Recovering byte {position}")
        print(f"Current signature: {recovered.hex()}")
        print("=" * 60)

        next_byte = find_byte(recovered)
        recovered += next_byte

        print(f"Recovered so far: {recovered.hex()}\n")

    print(f"Signature: {recovered.hex()}")


if __name__ == "__main__":
    signature = HMAC_SHA1(key, FILE).bytes()
    print("Valid signature (just to validate):", signature.hex())
    find_valid_mac()