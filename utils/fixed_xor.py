def fixed_xor(a, b):
    """
    Returns the byte-wise XOR of two equal length byte strings
    """
    assert len(a) == len(b)
    
    return bytes(x ^ y for x, y in zip(a, b))