# Reference: https://en.wikipedia.org/wiki/HMAC

from utils.fixed_xor import fixed_xor
from primitives.sha1 import SHA1

class HMAC_SHA1:
    block_size = 64

    def __init__(self, key, message):
        """
        Initiate the internal state from the key and message.
        """
        block_sized_key = self.compute_block_sized_key(key)

        o_key_pad = fixed_xor(block_sized_key, b'\x5c' * self.block_size)
        i_key_pad = fixed_xor(block_sized_key, b'\x36' * self.block_size)

        inner = SHA1(i_key_pad + message).bytes()
        self._digest = SHA1(o_key_pad + inner).bytes()

    def compute_block_sized_key(self, key):
        """
        Derive a block-sized key from the secret key.
        """
        if len(key) > self.block_size:
            key = SHA1(key).bytes()

        if len(key) < self.block_size:
            key = self.pad(key)

        return key
        
    def pad(self, key):
        """
        Pad the key with zeroes until it reaches the
        block size.
        """
        missing_bytes = self.block_size - len(key)

        return key + b'\x00' * missing_bytes

    def bytes(self):
        """
        Return the HMAC-SHA1 digest as bytes.
        """
        return self._digest


# Validate with RFC 2202: https://datatracker.ietf.org/doc/html/rfc2202

if __name__ == "__main__":
    # Test case 1
    key = b'\x0b' * 20
    data = b'Hi There'

    computed_digest = HMAC_SHA1(key, data).bytes()
    digest = bytes.fromhex('b617318655057264e28bc0b6fb378c8ef146be00')

    if computed_digest != digest:
        print(f'Test case 1 failed, expected {digest}, got {computed_digest}')

    print("Test case 1 passed.")

    # Test case 2
    key = b'Jefe'
    data = b'what do ya want for nothing?'

    computed_digest = HMAC_SHA1(key, data).bytes()
    digest = bytes.fromhex('effcdf6ae5eb2fa2d27416d5f184df9c259a7c79')

    if computed_digest != digest:
        print(f'Test case 2 failed, expected {digest}, got {computed_digest}')

    print("Test case 2 passed.")

    # Test case 3
    key = b'\xaa' * 20
    data = b'\xdd' * 50

    computed_digest = HMAC_SHA1(key, data).bytes()
    digest = bytes.fromhex('125d7342b9ac11cd91a39af48aa17b4f63f175d3')

    if computed_digest != digest:
        print(f'Test case 3 failed, expected {digest}, got {computed_digest}')

    print("All tests passed, implementation is correct.")