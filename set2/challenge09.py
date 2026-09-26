# Implement PKCS#7 padding

from primitives.pkcs7 import pkcs7_padding

def validate():
    """
    Validate the pkcs7 function pads the
    message as expected
    """
    msg = b'YELLOW SUBMARINE'
    expected = b'YELLOW SUBMARINE\x04\x04\x04\x04'

    padded = pkcs7_padding(msg, 20)
    
    if padded == expected:
        print("Implementation is correct")

if __name__ == "__main__":
    validate()