from primitives.pkcs7 import pkcs7_padding, pkcs7_unpadding
from primitives.aes import BLOCK_LEN, decrypt_block, encrypt_block

def aes_ecb_decrypt(ct, key):
    blocks = [ct[i:i+BLOCK_LEN] for i in range(0, len(ct), BLOCK_LEN)]

    pt = b""
    for block in blocks:
        pt += decrypt_block(block, key)

    return pkcs7_unpadding(pt, BLOCK_LEN)

def aes_ecb_encrypt(pt, key):
    padded = pkcs7_padding(pt, BLOCK_LEN)
    blocks = [padded[i:i+BLOCK_LEN] for i in range(0, len(padded), BLOCK_LEN)]

    ct = b""
    for block in blocks:
        ct += encrypt_block(block, key)

    return ct