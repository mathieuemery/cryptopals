def encrypt(message, key):
    return bytes(
        byte ^ key[i % len(key)]
        for i, byte in enumerate(message)
    )

if __name__ == "__main__":
    pt = b"""Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
    key = b"ICE"

    ct = encrypt(pt, key).hex()

    if (ct == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427276527"
                                        "2a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"):
        print("Implementation is correct")