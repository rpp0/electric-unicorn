import matplotlib.pyplot as plt
from leakage_functions import get_leakages


class LeakagePlot:
    def __init__(self, emulation_results, leakage_function):
        self.emulation_results = emulation_results
        self.leakage_function = leakage_function

    def _get_points(self):
        points = []
        for emulation_result in self.emulation_results:
            leakages = get_leakages(self.leakage_function, emulation_result)
            if type(leakages) is list:
                points.extend(leakages)
            else:
                points.append(leakages)
        return points

    def show(self):
        points = self._get_points()
        LeakagePlot.plot(points, None, title="Leakage over time using %s" % self.leakage_function.__name__)

    @staticmethod
    def plot(points, labels, title="Leakage over time"):
        plt.title(title)
        plt.plot(points, label="Leakage")
        if labels is not None:
            for label in labels:
                pass
        plt.legend()
        plt.show()
