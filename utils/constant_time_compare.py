# Credit: https://securitypitfalls.wordpress.com/2018/08/03/constant-time-compare-in-python/

def constant_time_compare(val1, val2):
    """Compare two strings in constant time"""
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= x ^ y
    return result == 0