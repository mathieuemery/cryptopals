# Single-byte XOR cipher

from collections import Counter

# Taken from https://www.math.stonybrook.edu/~scott/papers/MSTP/crypto/2I_m_Substitute.html
english_distribution = {
    'a': 8.167, 'b': 1.492, 'c': 2.802, 'd': 4.271, 'e': 12.702, 'f': 2.228,
    'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153, 'k': 0.772, 'l': 4.025,
    'm': 2.406, 'n': 6.749, 'o': 7.507, 'p': 1.929, 'q': 0.095, 'r': 5.987,
    's': 6.327, 't': 9.056, 'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150,
    'y': 1.974, 'z': 0.074
}


def clean_text(text):
    """
    Lower all alphabetic characters
    """
    return ''.join(c.lower() for c in text if c.isalpha())

# Reference: https://en.wikipedia.org/wiki/Index_of_coincidence
def calculate_index_of_coincidence(text):
    """
    Computes the probability that two randomly selected
    characters from the text are identical
    """
    text = clean_text(text)
    n = len(text)

    if n <= 1:
        return 0

    freq = Counter(text)

    return sum(
        freq[c] * (freq[c] - 1)
        for c in freq
    ) / (n * (n - 1))


# Reference: https://en.wikipedia.org/wiki/Chi-squared_test
def chi_squared(text):
    """
    Compute the chi-squared statistic between the text's character
    distribution and the expected English letter frequencies.
    """
    text = clean_text(text)
    n = len(text)

    if n == 0:
        return float('inf')

    freq = Counter(text)

    score = 0

    for letter, percentage in english_distribution.items():
        expected = n * percentage / 100
        observed = freq.get(letter, 0)

        score += (observed - expected) ** 2 / expected

    return score


def decrypt(ct):
    """
    Bruteforce all 256 possible keys and compute the
    index of coincidence and the chi squared for each
    decryption with this key
    """
    data = bytes.fromhex(ct)
    candidates = []

    for key in range(256):
        plaintext = bytes(b ^ key for b in data)

        # Reject non-printable ASCII
        if not all(32 <= b <= 126 for b in plaintext):
            continue

        pt = plaintext.decode('ascii')

        chi = chi_squared(pt)
        ic = calculate_index_of_coincidence(pt)

        candidates.append((chi, key, ic, pt))

    # Lower chi-squared = more English-like
    candidates.sort(key=lambda x: x[0])

    return candidates

def decrypt_challenge():
    """
    Decrypt the provided ciphertext
    """
    ct = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

    candidates = decrypt(ct)

    for chi, key, ic, plaintext in candidates[:10]:
        print(
            f"key={key:3d} "
            f"chi²={chi:8.2f} "
            f"IC={ic:.4f} "
            f"plaintext={plaintext!r}"
        )

if __name__ == "__main__":
    decrypt_challenge()