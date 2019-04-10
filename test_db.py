import unittest
import numpy as np
from emulationdbhdf5 import FullEmulationDBHDF5
from time import time


class TestFullEmulationDBHDF5(unittest.TestCase):
    def test_store(self):
        db = FullEmulationDBHDF5()
        db.open("/tmp/test.h5", trace_length=2*20000, mode='w')

        t0meta = (time(), 11500, np.array(bytearray(b"\x00"*32), dtype=np.uint8), np.array(bytearray(b"\x00"*76), dtype=np.uint8), np.array([], dtype=np.uint8), np.array([], dtype=np.uint8))
        t1meta = (time(), 11500, np.array(bytearray(b"\x00" * 33), dtype=np.uint8), np.array(bytearray(b"\x00" * 75), dtype=np.uint8), np.array([], dtype=np.uint8), np.array([], dtype=np.uint8))
        t0t0 = (np.array([1, 2, 3], dtype=np.uint64), np.array([2, 3, 4], dtype=np.uint64), np.array([0, 1, 2], dtype=np.uint64))
        t0t1 = (np.array([1, 2, 3, 5, 6], dtype=np.uint64), np.array([2, 3, 4, 5, 6], dtype=np.uint64), np.array([2, 3, 3, 3, 3, 3], dtype=np.uint64))
        t1t0 = (np.array([2, 3, 4], dtype=np.uint64), np.array([4, 5, 6], dtype=np.uint64), np.array([0, 1, 6], dtype=np.uint64))
        t1t1 = (np.array([2, 2, 3, 5, 6], dtype=np.uint64), np.array([3, 3, 4, 5, 6], dtype=np.uint64), np.array([2, 3, 3, 3, 3, 4], dtype=np.uint64))

        example_traces = np.array([
            [t0t0, t0t1]*20000,
            [t1t0, t1t1]*20000,
            [t0t1, t1t0]*20000,
        ], dtype=db.leakage_dtype)
        example_meta = [
            t0meta,
            t1meta,
            t1meta,
        ]
        example_rip = [
            0x4141242,
            0x2439094,
            0x1231231
        ]

        num_traces = len(example_traces)
        for i in range(num_traces):
            trace = example_traces[i]
            meta = example_meta[i]
            rip = example_rip[i]
            db.add_trace(trace, meta, rip, memory_trace=None)

        self.assertListEqual(list(db.get_trace(0)[0][0]), [1, 2, 3])  # Trace 0, t 0, old value
        self.assertListEqual(list(db.get_trace(0)[0][1]), [2, 3, 4])  # Trace 0, t 0, new value
        self.assertListEqual(list(db.get_trace(0)[0][2]), [0, 1, 2])  # Trace 0, t 0, indices
        self.assertListEqual(list(db.get_trace(0)[1][0]), [1, 2, 3, 5, 6])  # Trace 0, t 1, old value
        self.assertListEqual(list(db.get_trace(0)[1][1]), [2, 3, 4, 5, 6])  # Trace 0, t 1, new value
        self.assertListEqual(list(db.get_trace(0)[1][2]), [2, 3, 3, 3, 3, 3])  # Trace 0, t 1, indices


if __name__ == '__main__':
    unittest.main()
