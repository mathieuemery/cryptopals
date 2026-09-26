# Break repeating-key XOR

import base64

def hamming_distance(a, b):
    """
    Count the number of bits that differs from a and b
    """
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def keysize_score(ciphertext, keysize, num_blocks=8):
    """
    Estimate how likely `keysize` is to be the repeating-key length
    """
    blocks = [
        ciphertext[i:i + keysize]
        for i in range(0, keysize * num_blocks, keysize)
    ]

    distances = []

    for i in range(len(blocks) - 1):
        for j in range(i + 1, len(blocks)):
            if len(blocks[i]) == keysize and len(blocks[j]) == keysize:
                distances.append(
                    hamming_distance(blocks[i], blocks[j]) / keysize
                )

    return sum(distances) / len(distances)


def score_english(data):
    """
    Score if the data provided seems to be english text.

    This is a bit naive but it works.
    """
    score = 0

    for byte in data:
        c = chr(byte)

        # Most common english letters
        if c in "ETAOIN SHRDLUetaoinshrdlu":
            score += 1

        if c == ' ':
            score += 2

        if 32 <= byte <= 126:
            score += 0.1
        else:
            score -= 5

    return score

def find_key(ciphertext, key_length):
    """
    Find the key depending on the key length previously found
    """
    key = bytearray()

    for i in range(key_length):
        subtext = ciphertext[i::key_length]

        best_key_byte = 0
        best_score = float("-inf")

        for key_byte in range(256):
            decrypted = bytes(c ^ key_byte for c in subtext)

            score = score_english(decrypted)

            if score > best_score:
                best_score = score
                best_key_byte = key_byte

        key.append(best_key_byte)

    return bytes(key)

def decrypt(ct, key):
    """
    Decrypt the ciphertext by xoring the key repeatedly
    """
    return bytes(
        byte ^ key[i % len(key)]
        for i, byte in enumerate(ct)
    )


def decrypt_challenge():
    """
    Decrypt the file provided by finding the key length
    and then bruteforce the key one byte at a time
    """
    with open("data/6.txt", "r") as f:
        ciphertext = base64.b64decode(f.read())

    scores = {}

    for keysize in range(2, 41):
        scores[keysize] = keysize_score(ciphertext, keysize)

    for keysize, score in sorted(scores.items(), key=lambda x: x[1])[:10]:
        print(keysize, score)

    key = find_key(ciphertext, 29)
    print(key)
    
    pt = decrypt(ciphertext, key)
    print(pt)

    with open('data/6_decrypted.txt', 'wb') as file:
        file.write(pt)

if __name__ == "__main__":
    decrypt_challenge()