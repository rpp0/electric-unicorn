import unittest
import numpy as np
from util import diff_numpy_arrays


class TestUtil(unittest.TestCase):
    def test_diff_numpy_arrays(self):
        a = np.array([1, 2, 3, 4, 5, 6, 7, 8, 9])
        b = np.array([0, 2, 3, 4, 6, 1, 7, 8, 10])
        old, new, ind = diff_numpy_arrays(a, b)

        old = list(old)
        new = list(new)
        ind = list(ind)
        self.assertListEqual(old, [1, 5, 6, 9])
        self.assertListEqual(new, [0, 6, 1, 10])
        self.assertListEqual(ind, [0, 4, 5, 8])


if __name__ == '__main__':
    unittest.main()
