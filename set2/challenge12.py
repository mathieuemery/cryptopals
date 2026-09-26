# Byte-at-a-time ECB decryption (Simple)

from primitives.aes_ecb import aes_ecb_encrypt
import base64

key = b'YELLOW SUBMARINE'

secret_pt = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
secret_length = len(base64.b64decode(secret_pt))

def encryption_oracle(input):
    """
    Add a prefix to a secret plaintext
    and encrypt the result with AES in ECB mode
    """
    secret = base64.b64decode(secret_pt)
    return aes_ecb_encrypt(input + secret, key)


def decrypt_ecb_byte_at_a_time():
    """
    Decrypt the ciphertext by adding a prefix to the
    secret message that is always one byte short. Allows
    to bruteforce the plaintext one byte at a time.

    Example: By providing a 15 byte long prefix, we'll get
    a first block like this: <prefix><first byte of plaintext>

    Once we know that, we can bruteforce the last byte until
    we find the same ciphertext for this block.

    Once we have it, we use a 14 byte input to get the next byte
    etc. until the plaintext is decrypted.

    Works because the output of AES in ECB mode is
    deterministic for the same input.
    """
    recovered = b""

    # Normally the length isn't known
    for n in range(secret_length):
        padding_length = 15 - (n % 16)
        prefix = b"A" * padding_length

        # Encrypt prefix + secret pt
        target = encryption_oracle(prefix)

        block_index = n // 16

        start = block_index * 16
        end = start + 16

        target_block = target[start:end]

        found = False

        for guess in range(256):
            candidate = prefix + recovered + bytes([guess])

            candidate_ct = encryption_oracle(candidate)

            candidate_block = candidate_ct[start:end]

            if candidate_block == target_block:
                recovered += bytes([guess])
                found = True
                break

        if not found:
            print("Could not find byte at position", n)
            break

    return recovered



if __name__ == "__main__":
    print(decrypt_ecb_byte_at_a_time())
