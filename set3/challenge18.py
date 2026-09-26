# Implement CTR, the stream cipher mode

from primitives.aes_ctr import aes_ctr_decrypt, aes_ctr_encrypt
import base64

ct_64 = b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
key= b"YELLOW SUBMARINE"
nonce = 0

def validate_implementation():
    """
    Validate that a message can be encrypted
    and decrypted properly
    """
    pt = b"Hello everyone !!!"
    nonce, ct = aes_ctr_encrypt(pt, key)
    pt2 = aes_ctr_decrypt(ct, key, nonce)

    assert pt == pt2

def decrypt_challenge():
    ct = base64.b64decode(ct_64)
    pt = aes_ctr_decrypt(ct, key, nonce)
    print(pt)

if __name__ == "__main__":
    validate_implementation()

    decrypt_challenge()