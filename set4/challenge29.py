# Ressource used: https://www.herongyang.com/Cryptography/SHA1-Message-Digest-Algorithm-Overview.html

from primitives.sha1_mac import compute_mac, verify_mac

import struct
from functools import reduce

class SHA1:
    """
    An implementation of the SHA-1 hash that allows
    setting a, b, c, d and e.
    """

    width = 32
    mask = 0xFFFFFFFF

    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

    def __init__(self, msg=None):
        """:param ByteString msg: The message to be hashed."""
        if msg is None:
            msg = b""

        self.msg = msg

        # Pre-processing: Total length is a multiple of 512 bits.
        ml = len(msg) * 8
        msg += b"\x80"
        msg += b"\x00" * (-(len(msg) + 8) % 64)
        msg += struct.pack(">Q", ml)

        # Process the message in successive 512-bit chunks.
        chunks = [msg[i : i + 64] for i in range(0, len(msg), 64)]
        self._process(chunks)

    def __repr__(self):
        """Returns a developer-friendly representation of the SHA-1 object."""
        if self.msg:
            return f"{self.__class__.__name__}({self.msg:s})"
        return f"{self.__class__.__name__}()"

    def __str__(self):
        """Returns the SHA-1 hash as a hexadecimal string."""
        return self.hexdigest()
    
    def __eq__(self, other):
        """Compares two SHA-1 objects by their internal hash state."""
        return self.h == other.h

    def int(self):
        """:return: The final hash value as an `int`."""
        return reduce(lambda x, y: (x << SHA1.width) | y, self.h)

    def bytes(self):
        """:return: The final hash value as a `bytes` object."""
        return struct.pack(">5L", *self.h)

    def hexbytes(self):
        """:return: The final hash value as hexbytes."""
        return self.hexdigest().encode()

    def hexdigest(self):
        """:return: The final hash value as a hexstring."""
        return "".join(f"{value:08x}" for value in self.h)

    @staticmethod
    def process(chunks, a, b, c, d, e):
        """Processes the message chunks through the SHA-1 compression function."""
        h = [a, b, c, d, e]

        for chunk in chunks:
            a, b, c, d, e = h

            w = list(struct.unpack(">16L", chunk))

            # Extend the sixteen 32-bit words into eighty 32-bit words
            for i in range(16, 80):
                value = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
                w.append(SHA1.lrot(value, 1))

            for i in range(len(w)):
                if i < 20:
                    f, k = d ^ (b & (c ^ d)), 0x5A827999
                elif i < 40:
                    f, k = b ^ c ^ d, 0x6ED9EBA1
                elif i < 60:
                    f, k = (b & c) | (d & (b | c)), 0x8F1BBCDC
                else:
                    f, k = b ^ c ^ d, 0xCA62C1D6

                temp = (SHA1.lrot(a, 5) + f + e + k + w[i]) & SHA1.mask
                e, d, c, b, a = d, c, SHA1.lrot(b, 30), a, temp

            # Add this chunk's hash to result so far
            h = [
                (h[0] + a) & SHA1.mask,
                (h[1] + b) & SHA1.mask,
                (h[2] + c) & SHA1.mask,
                (h[3] + d) & SHA1.mask,
                (h[4] + e) & SHA1.mask,
            ]
        return h

    @staticmethod
    def lrot(value, n):
        """Performs a left circular rotation on a 32-bit value."""
        lbits, rbits = (value << n) & SHA1.mask, value >> (SHA1.width - n)
        return lbits | rbits

def compute_md_padding(message_len):
    """Computes the SHA-1 padding required for a message of the given length."""
    ml = message_len * 8

    padding = b"\x80"
    padding += b"\x00" * ((56 - (message_len + 1) % 64) % 64)
    padding += struct.pack(">Q", ml)

    return padding


def forge_message(original_message, original_mac):
    """Creates a forged message and MAC by exploiting SHA-1's length-extension property."""
    a, b, c, d, e = struct.unpack(">5L", original_mac)

    # Create the original padding for the message and the 16 key bytes
    glue_padding = compute_md_padding(len(original_message) + 16)

    extension = b";admin=true"

    forged_message_len = (
        16 # Key length
        + len(original_message)
        + len(glue_padding)
        + len(extension)
    )

    extension_padding = compute_md_padding(forged_message_len)

    data_to_process = extension + extension_padding

    chunks = [
        data_to_process[i:i + 64]
        for i in range(0, len(data_to_process), 64)
    ]

    forged_mac = SHA1.process(chunks, a, b, c, d, e)

    # Convert the resulting five 32-bit words to bytes
    forged_mac = struct.pack(">5L", *forged_mac).hex()

    forged_message = original_message + glue_padding + extension

    return forged_message, forged_mac


def attack_construction():
    """Attack the construction to validate the attack works."""
    message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

    mac = compute_mac(message)
    mac_bytes = bytes.fromhex(mac)
    
    forged_message, forged_mac = forge_message(message, mac_bytes)

    if verify_mac(message, mac):
        print("Original mac is correct")

    if verify_mac(forged_message, forged_mac):
        print("Forged mac is correct")
        print("Successfully used message: ", forged_message)


if __name__ == "__main__":
    attack_construction()