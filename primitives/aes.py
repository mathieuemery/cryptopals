from Crypto.Cipher import AES
import secrets

BLOCK_LEN = 16

def new_key():
    return secrets.token_bytes(16)

def decrypt_block(ct, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ct)

def encrypt_block(pt, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pt)