# Detect AES in ECB mode

import base64

def detect_aes_ecb(ciphertexts):
    """
    Detect which lines have repeated ciphertext blocks
    """
    for line_num, ct in enumerate(ciphertexts):
        blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
        seen = set()

        for i, block in enumerate(blocks):
            if block in seen:
                print(f"Ciphertext {line_num}: duplicate block at index {i}: {block.hex()}")
                return line_num
            else:
                seen.add(block)


def find_encrypted_line():
    """
    Find the line encrypted with ECB in the file provided
    """
    with open("data/8.txt", "r") as f:
        ciphertexts = [base64.b64decode(line.strip()) for line in f]

    print(detect_aes_ecb(ciphertexts))

if __name__ == "__main__":
    find_encrypted_line()