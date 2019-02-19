#!/usr/bin/env python

import lief
import os
import numpy as np
import matplotlib.pyplot as plt
import argparse
from electricunicorn import trace_register_hws


class EUException(Exception):
    pass


class Elf:
    def __init__(self, meta, memory):
        self.meta = meta
        self.memory = memory
        self.sp = None
        self._create_stack()
        self.pmk = next(s for s in meta.symbols if s.name == 'fake_pmk').value
        self.ptk = next(s for s in meta.symbols if s.name == 'fake_ptk').value
        self.stop_addr = next(s for s in meta.symbols if s.name == 'stop').value

    def _create_stack(self):
        self.memory.extend(bytearray(1024*1024))
        self.sp = len(self.memory)
        self.memory.extend(bytearray(1024*1024))


class ElectricUnicorn:
    def __init__(self, elf_path, dataset_path=None):
        self.elf_path = os.path.abspath(elf_path)
        self.elf = self._analyze_elf()
        self.dataset_path = dataset_path

    def _analyze_elf(self):
        if self.elf_path is None:
            raise EUException("Elf path not set")

        elf = lief.parse(self.elf_path)

        begin_addrs = [s.virtual_address for s in elf.segments]
        end_addrs = [s.virtual_address + len(s.content) for s in elf.segments]
        end_addr = max(end_addrs)
        buffer = bytearray(end_addr)

        for s in elf.segments:
            begin = s.virtual_address
            end = s.virtual_address + len(s.content)
            buffer[begin:end] = s.content
            print("[%d:%d] -> %s" % (begin, end, str(s.content)))

        return Elf(elf, buffer)

    def patch(self, address, data):
        self.elf.memory[address:address + len(data)] = data

    def start(self):
        max_mem_bytes = 1024*1024*1024
        results = np.zeros(int(max_mem_bytes / np.ushort().nbytes), dtype=np.ushort)
        test_key = b"\xf8\x6b\xff\xcd\xaf\x20\xd2\x44\x4f\x5d\x36\x61\x26\xdb\xb7\x5e\xf2\x4a\xba\x28\xe2\x18\xd3\x19\xbc\xec\x7b\x87\x52\x8a\x4c\x61"
        self.patch(self.elf.pmk, test_key)
        # TODO Change Cython code to get this stuff from self.elf data structure
        trace_register_hws(results, self.elf.memory, len(self.elf.memory), self.elf.meta.entrypoint, self.elf.sp, self.elf.pmk, self.elf.ptk, self.elf.stop_addr)

        if self.dataset_path is None:
            plt.plot(results)
            plt.show()
        else:
            print("Saving dataset...")


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description='')
    arg_parser.add_argument('elf_path', type=str, help='Path to the ELF to analyze.')
    arg_parser.add_argument('dataset_path', nargs='?', type=str, default=None, help='Path to store the simulated traces in.')
    args, _ = arg_parser.parse_known_args()

    e = ElectricUnicorn(args.elf_path, dataset_path=args.dataset_path)
    e.start()
