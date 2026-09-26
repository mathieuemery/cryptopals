# Break fixed-nonce CTR statistically


from primitives.aes_ctr import encrypt_block, make_counter_block
from utils.xor import xor
import base64

key = b"YELLOW SUBMARINE"
nonce = 0

# Reference: https://en.wikipedia.org/wiki/Letter_frequency
freq = {
    'e': 13.0, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7, 's': 6.3,
    'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8, 'u': 2.4, 'm': 2.4,
    'w': 2.2, 'f': 2.0, 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5, 'v': 0.98,
    'k': 0.77, 'j': 0.15, 'x': 0.15, 'q': 0.095, 'z': 0.074, ' ': 15.0
}

def ctr_encrypt(pt, key):
    """
    Encrypt a message using AES in CTR mode.

    Used so we can reuse the nonce which is not
    possible with the implementation I made
    """
    blocks = [pt[i:i+16] for i in range(0, len(pt), 16)]

    ctr = 0
    ct = b""
    for block in blocks:
        counter = make_counter_block(nonce, ctr)
        enc_c = encrypt_block(counter, key)

        ct += xor(block, enc_c)
        ctr += 1
    
    return nonce, ct

def encrypt_cts(pts):
    """
    Encrypt all plaintexts with an AES CTR
    implementation that reuses the nonce
    """
    cts = []

    for pt in pts:
        nonce, ct = ctr_encrypt(pt, key)
        # Don't need the nonce here
        cts.append(ct)

    return cts


def break_ctr(pts):
    """
    Decrypt the ciphertexts that have been encrypted
    with AES CTR and a repeated nonce.
    
    For all ciphertexts, bruteforce the keystream and
    and decrypt the byte related with the guess. Keep 
    the keystream where all the decrypted bytes (one 
    per ciphertext) are the closest to english language.
    """
    cts = encrypt_cts(pts)
    max_len = max(len(c) for c in cts)

    keystream = bytearray(max_len)

    for pos in range(max_len):
        active_cts = [c for c in cts if len(c) > pos]
        best_score = -1000
        best_byte = 0

        for candidate in range(256):
            current_score = 0

            # A bit naive but it worked
            for c in active_cts:
                decrypted_char = chr(c[pos] ^ candidate)
                char_lower = decrypted_char.lower()

                if char_lower in freq:
                    current_score += freq[char_lower]
                elif decrypted_char in ".,;:'?!-\"":
                    current_score += 1.0
                elif 32 <= ord(decrypted_char) <= 126:
                    current_score += 0.1
                else:
                    current_score -= 50.0  # Reject non-printable ASCII

            if current_score > best_score:
                best_score = current_score
                best_byte = candidate

        keystream[pos] = best_byte

    # To fix first byte of the keystream
    # that is always wrong with this implementation
    keystream[0] = cts[0][0] ^ ord('I')
    

    # Decrypt the ciphertexts using the keystream
    for i, c in enumerate(cts):
        decrypted = xor(c, keystream[:len(c)])
        print(f"{i:2d}: {decrypted.decode('ascii', errors='ignore')}")


def decrypt_challenge():
    with open('data/20.txt', 'rb') as file:
        pts_b64 = file.readlines()

    pts = [base64.b64decode(x) for x in pts_b64]

    break_ctr(pts)


if __name__ == "__main__":
    decrypt_challenge()