# Implement the MT19937 Mersenne Twister RNG

from primitives.mt19937 import mt19937


# Reference: https://gist.github.com/mimoo/8e5d80a2e236b8b6f5ed
expected = [3521569528,
                            1101990581,
                            1076301704,
                            2948418163,
                            3792022443,
                            2697495705,
                            2002445460,
                            502890592,
                            3431775349,
                            1040222146]

def validate():
    """
    Validate the implementation returns the
    expected random numbers
    """
    prng = mt19937(1131464071)

    for i in range(10):
        assert prng.random_uint32() == expected[i]

    print("Implementation is valid")


if __name__ == "__main__":
    validate()