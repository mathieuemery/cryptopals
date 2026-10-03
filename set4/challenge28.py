# Implement a SHA-1 keyed MAC

from primitives.sha1_mac import compute_mac, verify_mac

def validate():
    """
    Validate it isn't possible to tamper
    a MAC created with SHA1-MAC.
    """
    message = bytearray(b"Hello everyone !")

    mac = compute_mac(message)
    
    assert verify_mac(message, mac)

    # Flip a bit on the message
    message[0] ^= 1

    assert not verify_mac(message, mac)

if __name__ == "__main__":
    validate()
    print("Couldn't tamper the message (good)")