#!/usr/bin/env python
import matplotlib.pyplot as plt
import numpy as np
import random
from matplotlib.colors import LogNorm
from mpl_toolkits.mplot3d import Axes3D


hw = [bin(x).count("1") for x in range(2**8)]
hw16 = [bin(x).count("1") for x in range(2**16)]


def hw32(x):
    hh = hw16[x >> 16]
    lh = hw16[x & 0xffff]
    return hh + lh


def plot_hw_dist(hws):
    values = set(hws)
    points = []
    for value in values:
        cnt_value = len([x for x in hws if x == value])
        points.append((value, cnt_value))
    plt.bar([x[0] for x in points], [x[1] for x in points])
    plt.show()


def xor_prob(key_input, attacker_input, possible_values, chain):
    # x: key input
    # y: leakage after attacker input
    for c in chain:  # XOR with previous values if chaining
        key_input = key_input ^ c
    xor_output = key_input ^ attacker_input
    leakage = hw[xor_output]

    impossible_values = set()
    for v in possible_values:
        orig_v = v
        for c in chain:  # XOR with previous values if chaining
            v = v ^ c
        if hw[v ^ attacker_input] != leakage:
            impossible_values.add(orig_v)
    possible_values.difference_update(impossible_values)

    # print(possible_values)
    prob = 1 / len(possible_values)
    return prob


def prob_given_hw():
    for observed_hamming in range(9):
        pyx = 1
        px = 1 / len(hw)
        py = len([x for x in hw if x == observed_hamming]) / len(hw)
        pxy = (pyx * px) / py
        print("Certainty of byte given HW %d: %f" % (observed_hamming, pxy))


def plot_xor_prob_2d():
    probs = np.zeros((256, 256))
    for i in range(256):
        for j in range(256):
            possible_values = set(range(256))
            prob = xor_prob(i, j, possible_values, [])
            probs[i, j] = prob
    print(probs)
    plt.ylabel("key")
    plt.xlabel("plaintext")
    plt.title("P(X|Y)")
    plt.imshow(probs, norm=LogNorm(vmin=0.014286, vmax=1), origin='lower', cmap='viridis')
    plt.show()

def plot_xor_prob_3d():
    #probs = np.zeros((256, 256, 256))
    X = []
    Y = []
    Z = []
    color = []

    for i in range(256):
        print("\r%d      " % i, end='')
        for j in range(256):
            possible_values = set(range(256))
            _ = xor_prob(i, j, possible_values, [])
            for k in range(256):
                p2 = set(possible_values)
                try:
                    prob = xor_prob(i, k, p2, [j])
                except ZeroDivisionError:
                    print("Warning: no solution for %02x xor %02x xor %02x given %s" % (i, j, k, str(possible_values)))
                    prob = 0
                #probs[i,j,k] = prob
                X.append(i)
                Y.append(j)
                Z.append(k)
                color.append(prob)
    print('')

    fig = plt.figure()
    ax = fig.add_subplot(111, projection='3d')
    ax.scatter(X, Y, Z, cmap='viridis', c=color, alpha=0.5)
    plt.title("P(X|Y,Z)")
    plt.show()


def num_guesses_until_find(n=100, avoid_duplicates=False, do_chain=False, random_input=False):
    results = []
    for i in range(n):
        key = random.randint(0, 255)
        prob = 0
        possible_values = set(range(256))
        steps = 0
        tries = []
        sweep = [0, 1, 2, 4, 8, 16, 32, 64, 128]
        chain = []
        while prob < 1.0:
            if random_input:
                attacker_input = random.randint(0, 255)
                if avoid_duplicates and not do_chain:  # If we are not chaining (might require same input) and avoiding duplicates, keep tabs on which values we already tried.
                    while attacker_input in tries:
                        attacker_input = random.randint(0, 255)
                tries.append(attacker_input)
            else:
                if len(sweep) == 0:
                    raise Exception
                attacker_input = sweep.pop(0)
                tries.append(attacker_input)
            prob = xor_prob(key, attacker_input, possible_values, chain)
            if do_chain:
                chain.append(attacker_input)
            steps += 1
        results.append(steps)
        print("Found %02x in %d steps (%s)" % (key, steps, ','.join(["%02x" % x for x in tries])))
    return results


if __name__ == "__main__":
    #plot_hw_dist(hw)
    #plot_xor_prob_3d()
    plot_xor_prob_2d()

    n = 10000
    results_random = num_guesses_until_find(n=n, random_input=True)
    results_sweep = num_guesses_until_find(n=n, random_input=False)
    normed = True
    plt.xlabel("Number of steps")
    plt.ylabel("Probability" if normed else "Frequency")
    plt.title("Probability distribution of number of Hamming leakages required to find byte under XOR")
    plt.hist(results_random, align='left', bins=range(min(results_random), max(results_random)+2), label="random", alpha=0.5, normed=normed)  # Do not change. Hist is really bugged
    plt.hist(results_sweep, align='left', bins=range(min(results_sweep), max(results_sweep) + 2), label="sweep", alpha=0.5, normed=normed)
    plt.xticks(range(min(results_random), max(results_random)+1))
    plt.legend()
    plt.show()

