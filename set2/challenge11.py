# An ECB/CBC detection oracle

from primitives.aes import new_key
from primitives.aes_cbc import new_iv, aes_cbc_encrypt
from primitives.aes_ecb import aes_ecb_encrypt
from primitives.pkcs7 import pkcs7_padding
import secrets


def rand_bytes():
    """
    Generate between 5 and 10
    random bytes
    """
    n = secrets.randbelow(6) + 5
    return secrets.token_bytes(n)


def encryption_oracle(plaintext):
    """
    Encrypt messages randomly in
    ECB or CBC mode
    """
    key = new_key()

    prefix = rand_bytes()
    suffix = rand_bytes()

    data = prefix + plaintext + suffix

    padded = pkcs7_padding(data, 16)

    if secrets.randbelow(2) == 0:
        print("Using ECB")
        ct = aes_ecb_encrypt(padded, key)
    else:
        print("Using CBC")
        iv = new_iv()
        ct = aes_cbc_encrypt(padded, key, iv)
    
    return ct


def detect_aes_ecb(ciphertext):
    """
    Detect a ciphertext was encrypted with AES
    in ECB mode by searching for repeatitions in the blocks
    """
    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    seen = set()

    for block in blocks:
        if block in seen:
            return True
        seen.add(block)

    return False


def identification_oracle(ct):
    """
    Return the name of the algorithm
    used to encrypt the message
    """
    if detect_aes_ecb(ct):
        return "AES-ECB"
    else:
        return "AES-CBC"


if __name__ == "__main__":
    pt = b"A" * 64
    
    for i in range(10):
        ct = encryption_oracle(pt)
        print(identification_oracle(ct))