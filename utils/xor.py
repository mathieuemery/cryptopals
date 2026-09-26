def xor(a: bytes, b: bytes) -> bytes:
    """
    Xor a and b which may not have the same lenght.

    Stops when reaching the end of the shortest one,
    the returned result has the same length as the
    shortest one.
    """
    return bytes(x ^ y for x, y in zip(a, b))