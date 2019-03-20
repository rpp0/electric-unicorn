import numpy as np
from util import EmulationResult


def _hw(integer: int):
    return bin(integer).count("1")


def new_leakage(_, new):
    return list(new)


def hamming_distance_sum_leakage(old, new):
    results = np.zeros(len(new))
    for i in range(len(new)):
        results[i] = _hw(old[i] ^ new[i])
    return np.sum(results)


def hamming_distance_leakage(old, new):
    results = []
    for i in range(len(new)):
        results.append(_hw(old[i] ^ new[i]))
    return results


def get_leakages(leakage_function, emulation_result: EmulationResult):
    leakages = leakage_function(emulation_result.old, emulation_result.new)
    return leakages
