# AES in ECB mode

import base64
from primitives.aes_ecb import decrypt_block

key = b'YELLOW SUBMARINE'

def decrypt_challenge():
    """
    Decrypt the file provided
    """
    with open("data/7.txt", "r") as f:
        ciphertext = base64.b64decode(f.read())

    pt = decrypt_block(ciphertext, key)
    print(pt)

    with open('data/7_decrypted.txt', 'wb') as file:
        file.write(pt)

if __name__ == "__main__":
    decrypt_challenge()