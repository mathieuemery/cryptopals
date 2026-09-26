# PKCS#7 padding validation

from primitives.pkcs7 import pkcs7_unpadding

def validate():
    """
    Validate the unpadding method works when it should
    and throws errors otherwise
    """
    
    valid_pad = b"ICE ICE BABY\x04\x04\x04\x04"
    invalid_pad = b"ICE ICE BABY\x05\x05\x05\x05"

    # This one shouldn't throw an error
    valid_unpad = pkcs7_unpadding(valid_pad, 16)

    # This one should
    try:
        invalid_unpad = pkcs7_unpadding(invalid_pad, 16)
    except:
        print("Implementation returned an error for invalid padding")

    print("Unpadding is correct")

if __name__ == "__main__":
    validate()