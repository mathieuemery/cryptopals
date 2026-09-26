# Clone an MT19937 RNG from its output

from primitives.mt19937 import mt19937

n = 624
u = 11
s = 7
b = 0x9d2c5680
t = 15
c = 0xefc60000
l = 18

# Reference: https://stackoverflow.com/questions/26481573/reversing-xor-and-bitwise-operation-in-python
def undo_right_shift_xor(y, shift):
    """
    Undo the operations from mt19937
    that do: y ^= y >> shift
    """
    x = y
    for _ in range(5):
        x = y ^ (x >> shift)
    return x & 0xffffffff


def undo_left_shift_xor(y, shift, mask):
    """
    Undo the operations from mt19937
    that do: y ^= (y << shift) & mask
    """
    x = y
    for _ in range(5):
        x = y ^ ((x << shift) & mask)
    return x & 0xffffffff

def untemper(y):
    """
    Reverse the tampering done before
    returning the random value
    """
    y = undo_right_shift_xor(y, l)
    y = undo_left_shift_xor(y, t, c)
    y = undo_left_shift_xor(y, s, b)
    y = undo_right_shift_xor(y, u)

    return y


def create_outputs():
    """
    Create the outputs required to reconstruct
    the internal state
    """
    # Seed won't be used to break the challenge
    prng = mt19937(0)

    outputs = []
    recovered_state = []
    for i in range(n):
        val = prng.random_uint32()
        outputs.append(val)
        recovered_state.append(untemper(val))
    
    return outputs, recovered_state, prng


def forge_generator(recovered_state):
    """
    Create a generator from the recovered state
    of another.

    It can then be used to guess the next random value.
    """
    forged = mt19937(0)

    forged.state_array = recovered_state.copy()
    forged.state_index = 0

    return forged


def break_challenge():
    """
    Recover the internal state and guess the next
    10 random values
    """
    outputs, recovered_state, original_prng = create_outputs()

    assert original_prng.state_array == recovered_state

    forged_prng = forge_generator(recovered_state)

    for _ in range(10):
        original_value = original_prng.random_uint32()
        forged_value = forged_prng.random_uint32()

        assert original_value == forged_value

    print("Successfully guessed the next 10 random values")


if __name__ == "__main__":
    break_challenge()