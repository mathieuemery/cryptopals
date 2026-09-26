# Implement CBC mode

from Crypto.Cipher import AES
from primitives.aes_cbc import new_iv, aes_cbc_decrypt, aes_cbc_encrypt
import base64

key = b"YELLOW SUBMARINE"

def test_implementation():
    """
    Validate we can encrypt and decrypt
    a message
    """
    iv = new_iv()
    pt = b"Hello everyone !!!"

    ct = aes_cbc_encrypt(pt, key, iv)

    decrypted = aes_cbc_decrypt(ct, key, iv)

    if pt == decrypted:
        print("Round-trip OK")


def decrypt_challenge():
    """
    Decrypt the file provided with AES
    in CBC mode
    """
    with open("data/10.txt", "r") as f:
        ciphertext = base64.b64decode(f.read())
    
    iv = b'\x00' * 16

    pt = aes_cbc_decrypt(ciphertext, key, iv)
    print(pt)

    with open('data/10_decrypted.txt', 'wb') as file:
        file.write(pt)


if __name__ == "__main__":
    test_implementation()
    decrypt_challenge()
    