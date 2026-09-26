# Break "random access read/write" AES CTR

from base64 import b64decode
from primitives.aes import BLOCK_LEN, new_key
from primitives.aes_ctr import encrypt_block, new_nonce, make_counter_block, xor
from primitives.aes_ecb import aes_ecb_decrypt

key = new_key()
nonce = new_nonce()

ecb_key = b"YELLOW SUBMARINE"

def ctr_encrypt(pt, key, ctr = 0):
    """
    Encrypt a message using AES in CTR mode.

    Used so we can reuse the nonce which is not
    possible with the implementation I made
    """
    blocks = [pt[i:i+16] for i in range(0, len(pt), 16)]

    ct = b""
    for block in blocks:
        counter = make_counter_block(nonce, ctr)
        ks = encrypt_block(counter, key)

        ct += xor(block, ks)
        ctr += 1
    
    return ct

def ctr_decrypt(ct, offset, m_len):
    """
    Decrypt `m_len` bytes at a given offset
    """
    start_block = offset // BLOCK_LEN
    end_block = (offset + m_len + BLOCK_LEN - 1) // BLOCK_LEN

    blocks = [ct[i:i+BLOCK_LEN] for i in range(0, len(ct), BLOCK_LEN)]

    pt = b""

    for ctr, block in enumerate(blocks[start_block:end_block], start=start_block):
        counter = make_counter_block(nonce, ctr)
        keystream = encrypt_block(counter, key)

        pt += xor(block, keystream[:len(block)])

    # Remove bytes before the offset
    offset_in_block = offset % BLOCK_LEN
    pt = pt[offset_in_block:]

    return pt[:m_len]


def edit(ct, offset, newtext):
    """
    Makes modifications to a ciphertext at a gien offset
    """
    original_pt = ctr_decrypt(ct, offset, len(newtext))

    # Reconstruct the keystream
    ks = ctr_encrypt(
        b"\x00" * len(newtext),
        key,
        ctr=offset // BLOCK_LEN
    )

    start = offset % BLOCK_LEN
    ks = ks[start:start + len(newtext)]

    # Encrypt the new message
    new_ct = xor(newtext, ks)

    return original_pt, ct[:offset] + new_ct + ct[offset + len(newtext):]



def break_random_access(ct):
    """
    We know ct = keystream xor pt, by editing and 
    giving the ct, we get keystream xor ct which
    gives us the pt.
    
    Another solution would be to provide only zeroes
    and recover the keystream.
    """
    return edit(ct, 0, ct)


def break_challenge():
    with open("data/25.txt") as f:
        ecb_ct = b64decode(f.read())

    pt = aes_ecb_decrypt(ecb_ct, ecb_key)
    
    ct = ctr_encrypt(pt, key)

    print(break_random_access(ct))


if __name__ == "__main__":
    break_challenge()