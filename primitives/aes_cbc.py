from Crypto.Cipher import AES
from primitives.pkcs7 import pkcs7_padding, pkcs7_unpadding
from primitives.aes_ecb import decrypt_block, encrypt_block
from utils.fixed_xor import fixed_xor
import secrets

BLOCK_SIZE = 16

def new_iv():
    """
    Generate a new 16 byte random iv
    """
    return secrets.token_bytes(16)

def aes_cbc_decrypt(ct, key, iv):
    """
    Decrypt a message using AES in CBC mode
    """
    blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]

    pt = b""

    previous = iv
    for block in blocks:
        before_xor = decrypt_block(block, key)
        pt += fixed_xor(previous, before_xor)
        previous = block

    return pkcs7_unpadding(pt, BLOCK_SIZE)

def aes_cbc_encrypt(pt, key, iv):
    """
    Encrypt a message using AES in CBC mode
    """
    padded = pkcs7_padding(pt, BLOCK_SIZE)
    blocks = [padded[i:i+BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
    previous = iv

    ct = b""
    for block in blocks:
        xored = fixed_xor(block, previous)
        enc = encrypt_block(xored, key)

        ct += enc
        previous = enc

    return ct
