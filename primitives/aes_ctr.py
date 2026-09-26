from primitives.aes import encrypt_block
from utils.xor import xor
import secrets
import struct

def new_nonce():
    """
    Generate a 64 bit nonce
    """
    return int.from_bytes(secrets.token_bytes(8), "little")

def make_counter_block(nonce, ctr):
    """
    Concatenate the nonce and the counter
    """
    return struct.pack("<QQ", nonce, ctr)

def aes_ctr_encrypt(pt, key):
    """
    Encryption using AES in CTR mode
    """
    blocks = [pt[i:i+16] for i in range(0, len(pt), 16)]
    nonce = new_nonce()

    ctr = 0
    ct = b""
    for block in blocks:
        counter = make_counter_block(nonce, ctr)
        enc_c = encrypt_block(counter, key)

        ct += xor(block, enc_c)
        ctr += 1
    
    return nonce, ct


def aes_ctr_decrypt(ct, key, nonce):
    """
    Decryption using AES in CTR mode
    """
    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]

    ctr = 0
    pt = b""
    for block in blocks:
        counter = make_counter_block(nonce, ctr)
        enc_c = encrypt_block(counter, key)

        pt += xor(block, enc_c)
        ctr += 1

    return pt