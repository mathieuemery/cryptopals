# Iterated Hash Function Multicollisions

from primitives.aes import BLOCK_LEN, decrypt_block, encrypt_block
from itertools import product

class CustomWeakMD:
    """
    Super insecure hash function based on AES.

    Uses a 16-bit internal state.
    """

    HASH_BITS = 16
    HASH_SIZE = HASH_BITS // 8

    def __init__(self, msg=None):
        # Chose a random start value for `H`
        self.H = 12345

        assert 0 <= self.H < 2**self.HASH_BITS

        if msg is not None:
            self.update(msg)


    def truncate_16(self, ciphertext):
        """
        Return the 16 first bytes of the ciphertext.
        """
        return int.from_bytes(ciphertext[:2], "big")

    
    def make_key(self):
        """
        Create an AES 128 bits key by repeating
        `H` 8 times.
        """
        return self.H.to_bytes(2, "big") * 8


    def update(self, msg):
        """
        Pad the message so the message's length is
        a multiple of the block size.

        Then encrypt each block and update H with
        the first 16 bits of the ciphertext.
        """
        padding_len = BLOCK_LEN - (len(msg) % BLOCK_LEN)
        msg += bytes([padding_len]) * padding_len

        for i in range(0, len(msg), BLOCK_LEN):
            block = msg[i:i + BLOCK_LEN]
            self.compress(block)

        return self

    
    def compress(self, block):
        """
        Process one message block using the current chaining state.
        """
        key = self.make_key()
        ciphertext = encrypt_block(block, key)
        self.H = self.truncate_16(ciphertext)
        return self.H


    def digest(self) -> bytes:
        """
        Return the 'hash' that was computed.
        """
        return self.H.to_bytes(self.HASH_SIZE, "big")


    def hexdigest(self) -> str:
        """
        Return the 'hash' as an hex-encoded string.
        """
        return self.digest().hex()


class CustomStrongMD:
    """
    Super insecure hash function based on AES.

    Uses a 32-bit internal state.
    """

    HASH_BITS = 32
    HASH_SIZE = HASH_BITS // 8

    def __init__(self, msg=None):
        # Chose a random start value for `H`
        self.H = 1234567

        assert 0 <= self.H < 2**self.HASH_BITS

        if msg is not None:
            self.update(msg)


    def truncate_32(self, ciphertext):
        """
        Return the 32 first bytes of the ciphertext.
        """
        return int.from_bytes(ciphertext[:4], "big")

    
    def make_key(self):
        """
        Create an AES 128 bits key by repeating
        `H` 8 times.
        """
        return self.H.to_bytes(4, "big") * 4


    def update(self, msg):
        """
        Pad the message so the message's length is
        a multiple of the block size.

        Then encrypt each block and update H with
        the first 16 bits of the ciphertext.
        """
        padding_len = BLOCK_LEN - (len(msg) % BLOCK_LEN)
        msg += bytes([padding_len]) * padding_len

        for i in range(0, len(msg), BLOCK_LEN):
            block = msg[i:i + BLOCK_LEN]
            self.compress(block)

        return self


    def compress(self, block):
        """
        Process one message block using the current chaining state.
        """
        key = self.make_key()
        ciphertext = encrypt_block(block, key)
        self.H = self.truncate_32(ciphertext)
        return self.H


    def digest(self) -> bytes:
        """
        Return the 'hash' that was computed.
        """
        return self.H.to_bytes(self.HASH_SIZE, "big")


    def hexdigest(self) -> str:
        """
        Return the 'hash' as an hex-encoded string.
        """
        return self.digest().hex()


def find_collisions(state=None):
    """
    Find two distinct blocks that produce the 
    same next state when compressed from the
    same starting state.
    """
    if state is None:
        state = CustomWeakMD().H

    seen = {}

    for i in range(2**16):
        block = i.to_bytes(BLOCK_LEN, "big")

        h = CustomWeakMD()
        h.H = state
        new_state = h.compress(block)

        if new_state in seen:
            return seen[new_state], block, new_state

        seen[new_state] = block

    return None


def build_multicollision(n):
    """
    Construct 2**n messages that all produce the same
    final state under the weak hash.

    Each round finds two blocks that collide from the
    current state. Since both blocks reach the same next
    state, either can be used in the following round.
    """
    state = CustomWeakMD().H
    pairs = []

    for _ in range(n):
        block_a, block_b, state = find_collisions(state)
        pairs.append((block_a, block_b))

    return pairs, state


def find_strong_collision(pairs):
    """
    Search for a collision under the strong hash among
    messages that already collide under the weak hash.
    """
    seen = {}

    for combination in product(*pairs):
        msg = b"".join(combination)
        digest = CustomStrongMD(msg).digest()

        if digest in seen:
            return seen[digest], msg, digest

        seen[digest] = msg

    return None


def attack_construction():
    """
    Find a collision on the weak hash and
    the strong hash at the same time.

    The weak hash has a 16-bit state, so we build
    2**16 messages that share the same weak-hash
    state.

    Hash these messages with the strong hash and
    check if we get a collision. If yes, we have
    a collision in the weak hash and the strong hash.
    """
    pairs, state = build_multicollision(16)
    msg1, msg2, digest = find_strong_collision(pairs)

    assert msg1 != msg2
    assert CustomStrongMD(msg1).digest() == CustomStrongMD(msg2).digest()
    assert CustomWeakMD(msg1).digest() == CustomWeakMD(msg2).digest()

    print("Found a collision on both hash functions !")
    print("Message 1:", msg1)
    print("Message 2:", msg2)
    print("Strong digest:", digest.hex())
    print("Weak digest:", CustomWeakMD(msg1).hexdigest())


if __name__ == "__main__":
    attack_construction()