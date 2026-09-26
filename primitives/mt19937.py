# Reference: https://en.wikipedia.org/wiki/Mersenne_Twister

class mt19937:
    n = 624
    m = 397
    w = 32
    r = 31
    UMASK = (1 << r) & 0xFFFFFFFF
    LMASK = (1 << r) - 1
    a = 0x9908b0df
    u = 11
    s = 7
    t = 15
    l = 18
    b = 0x9d2c5680
    c = 0xefc60000
    f = 1812433253

    def to_int32(self, x):
        return x & 0xFFFFFFFF

    def __init__(self, seed):
        """
        State initiation for the Mersenne Twister
        """
        self.state_array = [0] * self.n

        seed = self.to_int32(seed)
        self.state_array[0] = seed

        for i in range(1, self.n):
            seed = self.to_int32(
                self.f * (seed ^ (seed >> (self.w - 2))) + i
            )
            self.state_array[i] = seed

        self.state_index = 0

    def random_uint32(self):
        """
        Based on the current state, generate a random
        uint32
        """
        k = self.state_index

        j = k - (self.n - 1)
        if j < 0:
            j += self.n

        x = self.to_int32(
            (self.state_array[k] & self.UMASK) |
            (self.state_array[j] & self.LMASK)
        )

        xA = x >> 1

        if x & 1:
            xA ^= self.a

        j = k - (self.n - self.m)
        if j < 0:
            j += self.n

        x = self.to_int32(self.state_array[j] ^ xA)
        self.state_array[k] = x

        k += 1
        if k >= self.n:
            k = 0

        self.state_index = k

        y = x
        y ^= y >> self.u
        y ^= (y << self.s) & self.b
        y ^= (y << self.t) & self.c
        y ^= y >> self.l

        return self.to_int32(y)
