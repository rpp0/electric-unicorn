import numpy as np
import matplotlib.pyplot as plt
from scipy import stats


def normalize_p2p(trace):
    return (trace - trace.min(0)) / trace.ptp(0)


def find_correlations(traces, targets, plot=False):
    num_traces, num_samples = traces.shape
    corr_values = []

    if num_traces < 2:
        raise Exception

    for i in range(num_samples):
        leakages = traces[:, i]
        corr = stats.pearsonr(leakages, targets)[0]
        # corr = np.correlate(leakages, targets)[0]
        if np.isnan(corr):
            corr = 0
        corr_values.append(corr)

    corr_values = np.array(corr_values)

    if plot:
        plt.plot(normalize_p2p(traces[0]), alpha=0.75)
        plt.plot(corr_values, alpha=0.75)
        plt.show()
