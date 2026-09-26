# Crack an MT19937 seed

from datetime import datetime
from primitives.mt19937 import mt19937
import time
import random


def random_delay():
    """
    Return a random value between 40 and 1000
    """
    return random.randint(40, 1000)

def fix_seed():
    """
    Wait a random time, seed the Mercenne Twister
    with the current time and then wait again a
    random time before generating a random value
    """
    time.sleep(random_delay())

    seed = int(time.time())
    prng = mt19937(seed)

    time.sleep(random_delay())

    return prng.random_uint32()

def break_seed(val):
    """
    We know it was ran the 07.09.2026 at around 20:30
    it is currently 20:43 we'll bruteforce all possible 
    seeds
    """
    
    start_time = datetime.strptime("2026-09-07 20:30:00", "%Y-%m-%d %H:%M:%S")
    start = int(start_time.timestamp())

    end_time = datetime.strptime("2026-09-07 20:43:00", "%Y-%m-%d %H:%M:%S")
    end = int(end_time.timestamp())

    for i in range(start, end):
        prng = mt19937(i)

        if prng.random_uint32() == val:
            return i

    raise ValueError("No value found")

def break_challenge():
    """
    From the random value, find back the seed
    """
    # Random value returned my MT19937
    val = 4197032898
    try:
        seed = break_seed(val)
        print("Seed was:",seed)

        dt = datetime.fromtimestamp(seed)
        print("MT was seeded the:",dt)
    except:
        print("Couldn't find the seed")

if __name__ == "__main__":
    break_challenge()

    