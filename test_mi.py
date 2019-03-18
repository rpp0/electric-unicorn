import unittest
import numpy as np
from mutinf import calc_mi, Observation
from sklearn.metrics import mutual_info_score


def scipy_mi(x, y):
    mi = mutual_info_score(x, y)
    return mi / np.log(2)


def scipy_mi_contingency(x, y):
    xy = np.histogram2d(x, y, bins=len(set(x)))[0]
    print(xy)
    mi = mutual_info_score(None, None, contingency=xy)
    return mi / np.log(2)


class TestMI(unittest.TestCase):
    def test_mi(self):
        obs = [
            Observation(time=0, key_bit=0, value=0, origin=0),
            Observation(time=0, key_bit=0, value=0, origin=0),
            Observation(time=0, key_bit=0, value=0, origin=0),
            Observation(time=0, key_bit=0, value=0, origin=0),
            Observation(time=0, key_bit=1, value=0, origin=0),
            Observation(time=0, key_bit=1, value=0, origin=0),
            Observation(time=0, key_bit=2, value=0, origin=0),
            Observation(time=0, key_bit=3, value=0, origin=0),
            Observation(time=0, key_bit=0, value=1, origin=0),
            Observation(time=0, key_bit=0, value=1, origin=0),
            Observation(time=0, key_bit=1, value=1, origin=0),
            Observation(time=0, key_bit=1, value=1, origin=0),
            Observation(time=0, key_bit=1, value=1, origin=0),
            Observation(time=0, key_bit=1, value=1, origin=0),
            Observation(time=0, key_bit=2, value=1, origin=0),
            Observation(time=0, key_bit=3, value=1, origin=0),
            Observation(time=0, key_bit=0, value=2, origin=0),
            Observation(time=0, key_bit=0, value=2, origin=0),
            Observation(time=0, key_bit=1, value=2, origin=0),
            Observation(time=0, key_bit=1, value=2, origin=0),
            Observation(time=0, key_bit=2, value=2, origin=0),
            Observation(time=0, key_bit=2, value=2, origin=0),
            Observation(time=0, key_bit=3, value=2, origin=0),
            Observation(time=0, key_bit=3, value=2, origin=0),
            Observation(time=0, key_bit=0, value=3, origin=0),
            Observation(time=0, key_bit=0, value=3, origin=0),
            Observation(time=0, key_bit=0, value=3, origin=0),
            Observation(time=0, key_bit=0, value=3, origin=0),
            Observation(time=0, key_bit=0, value=3, origin=0),
            Observation(time=0, key_bit=0, value=3, origin=0),
            Observation(time=0, key_bit=0, value=3, origin=0),
            Observation(time=0, key_bit=0, value=3, origin=0),
        ]

        my_mi = calc_mi(obs)

        x_vals = [o.key_bit for o in obs]
        y_vals = [o.value for o in obs]
        ref_mi = scipy_mi(x_vals, y_vals)

        self.assertAlmostEqual(my_mi, ref_mi)


if __name__ == '__main__':
    unittest.main()
