# The CBC padding oracle

from primitives.pkcs7 import pkcs7_unpadding
from primitives.aes import new_key
from primitives.aes_cbc import BLOCK_SIZE, aes_cbc_encrypt, aes_cbc_decrypt, new_iv
from utils.fixed_xor import fixed_xor
import random

pts = [
    b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
]

# Generate a new unknown key
key = new_key()

def random_pt():
    """
    Choose a random plaintext in the list
    """
    return random.choice(pts)

def encryption_oracle(pt):
    """
    Encrypt the plaintext with AES in CBC mode
    """
    iv = new_iv()
    ct = aes_cbc_encrypt(pt, key, iv)

    return iv, ct


def decryption_oracle(ct, iv):
    """
    Decrypt the ciphertext and catches the error
    in case the padding is not valid
    """
    try:
        aes_cbc_decrypt(ct, key, iv)
        return True
    except:
        return False


def find_one_block(previous, target, oracle):
    """
    Recover plaintext for:

    P = AES_DEC(target) XOR previous

    by modifying `previous` and asking the padding oracle
    about `modified_previous || target`.
    """

    intermediate = bytearray(BLOCK_SIZE)
    plaintext = bytearray(BLOCK_SIZE)

    for byte_num in reversed(range(BLOCK_SIZE)):
        pad = BLOCK_SIZE - byte_num

        modified = bytearray(previous)

        # Make all bytes we've already solved decrypt to `pad`.
        for j in range(byte_num + 1, BLOCK_SIZE):
            modified[j] = intermediate[j] ^ pad

        for guess in range(256):
            modified[byte_num] = guess

            candidate = bytes(modified) + target

            if not oracle(candidate):
                continue

            if byte_num == BLOCK_SIZE - 1:
                check = bytearray(modified)
                check[byte_num - 1] ^= 1

                if not oracle(bytes(check) + target):
                    continue

            intermediate[byte_num] = guess ^ pad
            plaintext[byte_num] = (
                intermediate[byte_num] ^ previous[byte_num]
            )

            print(
                f"byte {byte_num:2d}: "
                f"0x{plaintext[byte_num]:02x} "
                f"({chr(plaintext[byte_num])!r})"
            )

            break

        else:
            raise RuntimeError(
                f"Could not find valid padding for byte {byte_num}"
            )

    return bytes(plaintext)


# Reference: https://www.iacr.org/archive/eurocrypt2002/23320530/cbc02_e02d.pdf
def padding_oracle_attack(ct, iv):
    """
    Padding Oracle Attack for a vulnerable implementation
    who indicates if the padding is valid or not
    for a decrypted plaintext
    """
    blocks = [
        ct[i:i + BLOCK_SIZE]
        for i in range(0, len(ct), BLOCK_SIZE)
    ]

    recovered = b""

    # Attack each ciphertext block independently.
    # For the first block, use the IV as previous block.
    for block_num, target in enumerate(blocks):

        if block_num == 0:
            previous = iv
        else:
            previous = blocks[block_num - 1]

        print(f"\n--- attacking block {block_num} ---")

        recovered += find_one_block(
            previous,
            target,
            lambda candidate: decryption_oracle(
                candidate[16:],
                candidate[:16]
            )
        )

    return pkcs7_unpadding(recovered, 16)


if __name__ == "__main__":
    pt = random_pt()
    iv, ct = encryption_oracle(pt)

    recovered = padding_oracle_attack(ct, iv)

    print("Original:", pt)
    print("Recovered:", recovered)

    if pt == recovered:
        print("\nThe attack worked")