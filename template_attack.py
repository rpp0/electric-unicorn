#!/usr/bin/python
import h5py
import struct
import numpy as np
import matplotlib.pyplot as plt
import pickle
from collections import defaultdict
from scipy.stats import multivariate_normal
from sklearn.decomposition import PCA

NUM_TRACES = 0
NUM_POI_TRACES = 5000
NUM_POIS = 6


class Template:
    def __init__(self):
        self.templates = defaultdict(lambda: [])
        self.averages = {}
        self.covariance = {}
        self.g = {}

    def add(self, key, trace):
        trace = trace + np.random.normal(loc=0.0, scale=0.001, size=len(trace))
        self.templates[key].append(trace)

    def build(self):
        for k in self.templates:
            key_traces = np.array(self.templates[k])
            self.averages[k] = np.mean(key_traces, axis=0)
            self.covariance[k] = np.cov(key_traces, rowvar=False)

    def save(self):
        with open("averages.p", "wb") as f:
            pickle.dump(self.averages, f)
        with open("covariance.p", "wb") as f:
            pickle.dump(self.covariance, f)

    def load(self):
        with open("averages.p", "rb") as f:
            self.averages = pickle.load(f)
        with open("covariance.p", "rb") as f:
            self.covariance = pickle.load(f)

    def match(self, trace):
        for k in self.averages:
            self.g[k] = multivariate_normal(self.averages[k], self.covariance[k], allow_singular=False)

        probs = np.zeros(max(self.g.keys()) + 1)

        for k in self.g:
            probs[k] = self.g[k].pdf(trace)

        return probs


def argmax_extract(trace, count=5, spread=100):
    trace = np.copy(trace)
    indices = []

    for i in range(count):
        index = np.argmax(trace)
        indices.append(index)
        for j in range(max(0, index-spread), min(len(trace), index+spread+1)):
            trace[j] = 0

    return indices


def get_pois(debug=True):
    with h5py.File("leakages.h5", "r") as f:
        num_traces = NUM_POI_TRACES or len(f["meta"])

        trace_groups = defaultdict(lambda: [])
        for i in range(num_traces):
            trace = f["register_leakages"][i]
            meta = f["meta"][i][0]
            template_key = get_template_key(meta["key"])
            trace_groups[template_key].append(trace)

        group_means = {}
        for group in trace_groups:
            traces = np.array(trace_groups[group])
            mean = np.mean(traces, axis=0)
            group_means[group] = mean

    sum = 0
    for g1 in group_means:
        for g2 in group_means:
            g1t = group_means[g1]
            g2t = group_means[g2]
            sum += np.abs(g1t - g2t)

    pois = argmax_extract(sum, count=NUM_POIS)

    if debug:
        for p in pois:
            plt.gca().annotate("", xy=(p, 0), xytext=(0, -60), textcoords='offset points', arrowprops=dict(arrowstyle="->"))
        plt.plot(sum)
        plt.show()

    return pois

def save_pois():
    print("Getting POIs")
    pois = get_pois()
    print(pois)
    with open("pois.p", "wb") as f:
        pickle.dump(pois, f)


def load_pois():
    pois = None
    with open("pois.p", "rb") as f:
        pois = pickle.load(f)
    return np.array(pois)


def save_pca():
    print("Doing PCA")
    with h5py.File("leakages.h5", "r") as f:
        num_traces = NUM_POI_TRACES or len(f["meta"])

        pca = PCA(n_components=NUM_POIS)
        pca.fit(f["register_leakages"][0:num_traces, :])

        with open("pca.p", "wb") as f:
            pickle.dump(pca, f)


def load_pca():
    pca = None
    with open("pca.p", "rb") as f:
        pca = pickle.load(f)
    return pca


def get_template_key(key):
    return bin(struct.unpack(">I", key[0:4])[0]).count("1")  # Hamming
    # return key[0]  # Byte


def build_template(pca):
    print("Building template")

    with h5py.File("leakages.h5", "r") as f:
        t = Template()
        num_traces = NUM_TRACES or len(f["meta"])
        for i in range(num_traces):
            trace = f["register_leakages"][i]
            meta = f["meta"][i][0]
            template_key = get_template_key(meta["key"])
            # t.add(template_key, pca.transform([trace])[0])  # PCA
            t.add(template_key, trace[pca])  # POIs
        t.build()
        t.save()


if __name__ == "__main__":
    #save_pca()
    #pca = load_pca()
    #build_template(pca)

    #save_pois()
    pois = load_pois()
    build_template(pois)

    print("Attacking")
    with h5py.File("leakages.h5", "r") as f:
        t = Template()
        t.load()

        num_traces = NUM_TRACES or len(f["meta"])
        for i in range(num_traces):
            trace = f["register_leakages"][i]
            meta = f["meta"][i][0]
            template_key = get_template_key(meta["key"])

            # probs = t.match(pca.transform([trace])[0])  # PCA
            probs = t.match(trace[pois])  # POIs
            guess = np.argmax(probs)
            maxprob = np.max(probs)
            print("Guess for key %d: %d (%.4f)" % (template_key, guess, maxprob))

