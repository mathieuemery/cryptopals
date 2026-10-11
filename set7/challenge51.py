# Compression Ratio Side-Channel Attacks
# Reference: https://en.wikipedia.org/wiki/CRIME

from primitives.aes_ctr import aes_ctr_encrypt
import string
import zlib

key = b'YELLOW SUBMARINE'
session_id = "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="
ALPHABET = string.ascii_letters + string.digits + "+/="

def format_request(comment: str):
    """
    Format the session id and the plaintext in
    an HTTP request.
    """
    body = (
        f"POST / HTTP/1.1\n"
        f"Host: hapless.com\n"
        f"Cookie: sessionid={session_id}\n"
        f"Content-Length: {len(comment)}\n"
        f"{comment}"
    )
    return body.encode("utf-8")


def compression_oracle(request):
    """
    Compress then encrypt a request and return
    the ciphertext's length.
    """
    compressed = zlib.compress(request)
    nonce, ct = aes_ctr_encrypt(compressed, key)
    return len(ct)


def guess_next_char(prefix):
    """
    Find the next candidates that generate
    the smallest size after compression.
    """
    results = []

    for char in ALPHABET:
        candidate = prefix + char
        request = format_request(candidate)
        length = compression_oracle(request)
        results.append((length, char))

    best_length = min(length for length, char in results)

    candidates = [
        char for length, char in results
        if length == best_length
    ]

    return candidates, best_length


def evaluate_guesses(prefix, candidates):
    """
    For each tied candidate, try every possible
    following character.
    """
    scores = {}

    for char in candidates:
        guess = prefix + char
        _, best_length = guess_next_char(guess)
        scores[char] = best_length

    best_length = min(scores.values())

    return [
        char for char, length in scores.items()
        if length == best_length
    ]


def exploit_compression():
    """
    Exploit the compression to 'bruteforce' the
    secret.

    If the content of the body contains the same values
    as the 'Cookie' header, the message should be
    compressed more efficiently.

    Knowing this, we can bruteforce the `session_id`
    byte-per-byte.
    """
    recovered = "sessionid="

    for _ in range(len(session_id)):
        candidates, best_length = guess_next_char(
            recovered
        )

        if len(candidates) > 1:
            candidates = evaluate_guesses(recovered, candidates)

        print(f"Prefix: {recovered}")
        recovered += candidates[0]

    return recovered


if __name__ == "__main__":
    recovered = exploit_compression()
    
    if recovered == "sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=":
        print("Found the correct token:", recovered)