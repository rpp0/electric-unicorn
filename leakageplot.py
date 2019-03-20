import matplotlib.pyplot as plt
import code
from leakage_functions import get_leakages
from addr2code import Addr2Code
from collections import namedtuple

Label = namedtuple("Label", ["t", "text"])


class LeakagePlot:
    def __init__(self, emulation_results, leakage_function):
        self.emulation_results = emulation_results
        self.leakage_function = leakage_function
        self.a2c = Addr2Code("hmac-sha1")
        self.t_to_point = {}

    def _get_points(self):
        points = []
        for emulation_result in self.emulation_results:
            self.t_to_point[emulation_result.t] = len(points)
            leakages = get_leakages(self.leakage_function, emulation_result)
            if type(leakages) is list:
                points.extend(leakages)
            else:
                points.append(leakages)
        return points

    def _get_labels(self):
        labels = []
        last_code = None

        for emulation_result in self.emulation_results:
            rip = emulation_result.rip
            code = self.a2c.get_code(rip)
            if code is not None:
                if code != last_code:
                    labels.append(Label(t=emulation_result.t, text=code))
            last_code = code

        return labels

    def show(self):
        points = self._get_points()
        labels = self._get_labels()
        self.plot(points, labels, title="Leakage over time using %s" % self.leakage_function.__name__)

    def hack(self):
        points = self._get_points()
        labels = self._get_labels()
        result = []
        sha_labels = []
        for i in range(len(labels)):
            if labels[i].text == 'sha1':
                sha_labels.append(labels[i])

        for i in range(len(sha_labels)):
            start = self.t_to_point[sha_labels[i].t]
            if i == len(sha_labels)-1:
                end = -1
            else:
                end = self.t_to_point[sha_labels[i + 1].t]
            result.append(points[start:end])

        code.interact("", local=locals())

    def plot(self, points, labels, title="Leakage over time"):
        plt.title(title)
        plt.plot(points, label="Leakage")
        if labels is not None:
            for label in labels:
                x = self.t_to_point[label.t]
                y = points[x]
                # plt.gca().text(x, y, label.text, size=12)
                plt.gca().annotate(label.text, xy=(x, y), xytext=(0, -60), textcoords='offset points', arrowprops=dict(arrowstyle="->"))
        plt.legend()
        plt.show()
