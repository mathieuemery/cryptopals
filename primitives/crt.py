# Reference: https://en.wikipedia.org/wiki/Chinese_remainder_theorem

def crt(n_0, c_0, n_1, c_1, n_2, c_2):
    """
    Use the Chinese Remainder Theorem to recover the value C
    modulo N = n_0 * n_1 * n_2 such that:
        C ≡ c_0 (mod n_0)
        C ≡ c_1 (mod n_1)
        C ≡ c_2 (mod n_2)
    """
    m_s_0 = n_1 * n_2
    m_s_1 = n_0 * n_2
    m_s_2 = n_0 * n_1

    n_012 = n_0 * n_1 * n_2

    return ((c_0 * m_s_0 * pow(m_s_0, -1, n_0)) + (c_1 * m_s_1 * pow(m_s_1, -1, n_1)) + (c_2 * m_s_2 * pow(m_s_2, -1, n_2))) % n_012