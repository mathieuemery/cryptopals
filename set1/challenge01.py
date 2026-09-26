# Convert hex to base64

from utils.hex_to_b64 import hex_to_b64

def validate_implementation():
    """
    Validate the hex_to_b64 produces the expected result
    """
    text = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

    res = hex_to_b64(text)

    if res == expected:
        print("Implementation is correct")


if __name__ == "__main__":
    validate_implementation()