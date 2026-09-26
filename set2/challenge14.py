# Byte-at-a-time ECB decryption (Harder)

from primitives.aes import BLOCK_LEN
from primitives.aes_ecb import aes_ecb_encrypt
import base64
import secrets

key = b"YELLOW SUBMARINE"

secret_pt = (
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
)

secret = base64.b64decode(secret_pt)
secret_length = len(secret)

prefix_length = secrets.randbelow(100)
random_prefix = secrets.token_bytes(prefix_length)

def encryption_oracle(user_input):
    """
    Create a plaintext with the structure:
    random_prefix + user_input + secret

    Encrypt this plaintext
    """
    return aes_ecb_encrypt(
        random_prefix + user_input + secret,
        key
    )


def get_blocks(ct):
    """
    Convert the ciphertext to blocks
    of `BLOCK_LEN` length
    """
    return [
        ct[i:i + BLOCK_LEN]
        for i in range(0, len(ct), BLOCK_LEN)
    ]


def find_alignment():
    """
    Find how many bytes we need to prepend so that our
    controlled input starts exactly on an AES block boundary.

    We use 32 zero bytes because once they are aligned,
    they contain at least two complete identical blocks.
    """

    for padding_len in range(BLOCK_LEN):

        controlled = b"\x00" * (padding_len + 32)

        ct = encryption_oracle(controlled)
        blocks = get_blocks(ct)

        for i in range(len(blocks) - 1):

            if blocks[i] == blocks[i + 1]:

                # We found two consecutive identical blocks.
                #
                # Since our controlled data is 32 zero bytes,
                # this means our controlled zeros are aligned.

                return padding_len, i

    raise RuntimeError("Could not find alignment")


def make_aligned_oracle():
    """
    Align the user_input to the start of a block
    """
    padding_len, first_zero_block = find_alignment()

    print("Alignment padding:", padding_len)
    print("First controlled block:", first_zero_block)

    def aligned_oracle(user_input):

        # Make our controlled input start at a block boundary.
        alignment = b"\x00" * padding_len

        ct = encryption_oracle(
            alignment + user_input
        )

        blocks = get_blocks(ct)

        # Remove everything before our controlled region.
        #
        # What remains is :
        #
        # user_input || secret
        return b"".join(blocks[first_zero_block:])

    return aligned_oracle


def decrypt_ecb_byte_at_a_time(oracle):
    """
    Decrypt the secret plaintext one byte at a
    time by first aligning the blocks with our
    input
    """
    recovered = b""

    for n in range(secret_length):

        # Number of bytes needed so that the unknown byte
        # ends up at the end of a block.
        padding_length = 15 - (n % BLOCK_LEN)

        padding = b"A" * padding_length

        block_index = n // BLOCK_LEN

        start = block_index * BLOCK_LEN
        end = start + BLOCK_LEN

        # Get the target ciphertext for:
        #
        # padding || secret
        target_ct = oracle(padding)

        target_block = target_ct[start:end]

        found = False

        for guess in range(256):

            candidate = (
                padding
                + recovered
                + bytes([guess])
            )

            candidate_ct = oracle(candidate)

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
    oracle = make_aligned_oracle()

    recovered = decrypt_ecb_byte_at_a_time(oracle)

    print("\nRecovered:")
    print(recovered)
