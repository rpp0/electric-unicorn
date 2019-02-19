#!/usr/bin/env python

import lief
import os
import numpy as np
import matplotlib.pyplot as plt
import argparse
from electricunicorn import trace_register_hws


def print_numpy_as_hex(np_array: np.ndarray):
    cnt = 0
    for elem in np_array.flat:
        cnt += 1
        print("%02x " % elem, end='')

        if cnt == 16:
            cnt = 0
            print('')
    if cnt != 0:
        print('')


def read_memory(memory: np.ndarray, address, length):
    return memory[address:address+length]


def write_memory(memory: np.ndarray, address, data: bytes):
    memory[address:address+len(data)] = bytearray(data)


class EUException(Exception):
    pass


class Elf:
    def __init__(self, meta, memory):
        self.meta = meta
        self.memory = memory
        self.sp = None
        self._symbol_address_map = {}
        self._create_stack()
        self._build_symbol_address_map()

    def _create_stack(self):
        self.memory.extend(bytearray(1024*1024))
        self.sp = len(self.memory)
        self.memory.extend(bytearray(1024*1024))

    def _build_symbol_address_map(self):
        for s in self.meta.symbols:
            self._symbol_address_map[s.name] = s.value

    def get_symbol_address(self, symbol_name):
        return self._symbol_address_map[symbol_name]


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

    def hmac_sha1(self, pmk, data):
        # Prepare memory
        local_memory = np.array(self.elf.memory, dtype=np.uint8)  # Make copy of memory
        write_memory(local_memory, self.elf.get_symbol_address('fake_pmk'), pmk)
        write_memory(local_memory, self.elf.get_symbol_address('data'), data)

        # Simulate
        results = trace_register_hws(local_memory, self.elf.meta.entrypoint, self.elf.sp, self.elf.get_symbol_address('stop'))
        print_numpy_as_hex(read_memory(local_memory, self.elf.get_symbol_address('fake_ptk'), 64))

        return results


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description='')
    arg_parser.add_argument('elf_path', type=str, help='Path to the ELF to analyze.')
    arg_parser.add_argument('dataset_path', nargs='?', type=str, default=None, help='Path to store the simulated traces in.')
    args, _ = arg_parser.parse_known_args()

    test_key = b"\xf8\x6b\xff\xcd\xaf\x20\xd2\x44\x4f\x5d\x36\x61\x26\xdb\xb7\x5e\xf2\x4a\xba\x28\xe2\x18\xd3\x19\xbc\xec\x7b\x87\x52\x8a\x4c\x61"
    e = ElectricUnicorn(args.elf_path, dataset_path=args.dataset_path)
    
    results = e.hmac_sha1(pmk=test_key, data=b"\x00"*76)
    if args.dataset_path is None:
        plt.plot(results)
        plt.show()
    else:
        print("Saving dataset...")
