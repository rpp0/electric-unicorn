import h5py
import numpy as np
from time import time


class FullEmulationDBHDF5:
    def __init__(self):
        self.database = None
        self.register_traces = None
        self.memory_traces = None
        self.meta = None
        self.rip = None
        self.leakage_dtype = np.dtype([('old', h5py.special_dtype(vlen=np.uint64)),
                                       ('new', h5py.special_dtype(vlen=np.uint64)),
                                       ('indices', h5py.special_dtype(vlen=np.uint64))])
        self.meta_dtype = np.dtype([('date', np.uint64),
                                    ('limit', np.uint64),
                                    ('key', h5py.special_dtype(vlen=np.uint8)),
                                    ('plaintext', h5py.special_dtype(vlen=np.uint8)),
                                    ('ciphertext', h5py.special_dtype(vlen=np.uint8)),
                                    ('mask', h5py.special_dtype(vlen=np.uint8))])

    def open(self, filename, trace_length, mode='a', traces_per_chunk=1):
        self.database = h5py.File(filename, mode)
        self.register_traces = self.database.create_dataset("register_leakages", shape=(0, trace_length), maxshape=(None, trace_length), chunks=(traces_per_chunk, trace_length), dtype=self.leakage_dtype, compression='gzip')
        self.memory_traces = self.database.create_dataset("memory_leakages", shape=(0, trace_length), maxshape=(None, trace_length), chunks=(traces_per_chunk, trace_length), dtype=self.leakage_dtype, compression='gzip')
        self.meta = self.database.create_dataset("meta", shape=(0, 1), maxshape=(None, 1), chunks=(traces_per_chunk, 1), dtype=self.meta_dtype)
        self.rip = self.database.create_dataset("rip", shape=(0, trace_length), maxshape=(None, trace_length), chunks=(traces_per_chunk, trace_length), dtype=np.uint64)

    def add_trace(self, register_trace, metadata, rip, memory_trace=None):
        # print("Adding %s" % register_trace)
        # Add register and memory traces
        self.register_traces.resize(self.register_traces.shape[0]+1, axis=0)
        self.memory_traces.resize(self.memory_traces.shape[0]+1, axis=0)

        self.register_traces[-1:] = register_trace
        if memory_trace is not None:
            self.memory_traces[-1:] = memory_trace
        else:
            self.memory_traces[-1:] = (np.array([], dtype=np.uint64), np.array([], dtype=np.uint64), np.array([], dtype=np.uint64))

        # Add metadata
        self.meta.resize(self.meta.shape[0]+1, axis=0)
        self.meta[-1:] = metadata

        # Add rip
        self.rip.resize(self.rip.shape[0]+1, axis=0)
        self.rip[-1:] = rip

        # Flush
        self.database.flush()

    def get_trace(self, trace_index, registers_only=True):
        if registers_only:
            return self.register_traces[trace_index, :]

    def __del__(self):
        if self.database:
            self.database.close()


class EmulationDBHDF5:
    def __init__(self):
        self.database = None
        self.register_leakages = None
        self.meta = None
        self.meta_dtype = np.dtype([('date', np.uint64),
                                    ('limit', np.uint64),
                                    ('key', h5py.special_dtype(vlen=np.uint8)),
                                    ('plaintext', h5py.special_dtype(vlen=np.uint8)),
                                    ('ciphertext', h5py.special_dtype(vlen=np.uint8)),
                                    ('mask', h5py.special_dtype(vlen=np.uint8))])

    def open(self, filename, trace_length, mode='a', traces_per_chunk=256):
        self.database = h5py.File(filename, mode)
        #self.register_leakages = self.database.get("register_leakages")
        #self.meta = self.database.get("meta")
        self.register_leakages = self.database.create_dataset("register_leakages", shape=(0, trace_length), maxshape=(None, trace_length), chunks=(traces_per_chunk, trace_length), dtype='uint16', compression='gzip')
        self.meta = self.database.create_dataset("meta", shape=(0, 1), maxshape=(None, 1), chunks=(traces_per_chunk, 1), dtype=self.meta_dtype)

    def add_trace(self, register_leakages, limit, key_bytes, plaintext_bytes, ciphertext_bytes, mask_bytes):
        if ciphertext_bytes is None:
            ciphertext_bytes = []
        if mask_bytes is None:
            mask_bytes = []
        key = np.array(bytearray(key_bytes), dtype=np.uint8)
        plaintext = np.array(bytearray(plaintext_bytes), dtype=np.uint8)
        ciphertext = np.array(bytearray(ciphertext_bytes), dtype=np.uint8)
        mask = np.array(bytearray(mask_bytes), dtype=np.uint8)

        metadata = (time(), limit, key, plaintext, ciphertext, mask)
        self.meta.resize(self.meta.shape[0]+1, axis=0)
        self.meta[-1:] = metadata

        self.register_leakages.resize(self.register_leakages.shape[0] + 1, axis=0)
        self.register_leakages[-1:] = register_leakages

    def get_trace(self, trace_index):
        return self.register_leakages[trace_index, :], self.meta[trace_index, :]
