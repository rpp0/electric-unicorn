import random
import struct
import numpy as np
from collections import namedtuple

EmulationResult = namedtuple("EmulationResult", ["t", "old", "new", "indices", "is_memory", "rip"])


class EUException(Exception):
    pass


class Ref:
    def __init__(self, x):
        self.value = x


def random_uniform(length):
    with open("/dev/urandom", "rb") as f:
        return f.read(length)


def random_hamming(length, subkey_size):
    if subkey_size == 1:
        format = "B"
    elif subkey_size == 2:
        format = "h"
    elif subkey_size == 4:
        format = "I"
    else:
        raise ValueError("Invalid subkey size")

    num_bits = subkey_size * 8

    result = b""
    for i in range(0, length, subkey_size):
        num_ones = random.randint(0, num_bits)
        num_zeros = num_bits - num_ones
        integer_str = (num_ones * "1") + (num_zeros * "0")
        shuffled_str = ''.join(random.sample(integer_str, num_bits))
        shuffled_int = int(shuffled_str, 2)
        result += struct.pack(format, shuffled_int)

    assert(len(result) == length)
    return result


def print_numpy_as_hex(np_array: np.ndarray, label: str=None):
    if label is not None:
        print(label + ": ")

    cnt = 0
    for elem in np_array.flat:
        cnt += 1
        print("%02x " % elem, end='')

        if cnt == 16:
            cnt = 0
            print('')
    if cnt != 0:
        print('')


def diff_numpy_arrays(old: np.ndarray, new: np.ndarray):
    if old.size != new.size:
        raise EUException("Numpy buffers cannot be different sizes")

    # Vectorized approach
    array_indices = np.arange(len(new))
    changed_values = (new - old) != 0
    old_diff = old[changed_values]
    new_diff = new[changed_values]
    diff_indices = array_indices[changed_values]

    return old_diff, new_diff, diff_indices
