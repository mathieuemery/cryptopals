import base64

def hex_to_b64(text):
    """
    Converts an hex string into its base64 representation
    """
    return base64.b64encode(bytes.fromhex(text)).decode()