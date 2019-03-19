#!/usr/bin/env python
import sys
sys.path.insert(0, '/home/pieter/projects/em/')


import lief
import os
import numpy as np
import matplotlib.pyplot as plt
import argparse
import binascii
import pickle
from datetime import datetime
from electricunicorn import trace_register_hws, emulate
from unicorn.x86_const import *
from dependencygraph import DependencyGraph, DependencyGraphKey
from inputs import InputMeta
from mutinf import MutInfAnalysis
from util import EUException, random_hamming, random_uniform, print_numpy_as_hex
from emulationstate import X64EmulationState
from leakage_functions import *

MEMCPY_NUM_INSTRUCTIONS = 39
MEMCPY_NUM_BITFLIPS = int(256 / 8)
HMACSHA1_NUM_INSTRUCTIONS = 44344
#HMACSHA1_NUM_INSTRUCTIONS = 6000
#HMACSHA1_NUM_INSTRUCTIONS = 500
HMACSHA1_NUM_BITFLIPS = 1


def read_memory(memory: np.ndarray, address, length):
    return memory[address:address+length]


def write_memory(memory: np.ndarray, address, data: bytes):
    memory[address:address+len(data)] = bytearray(data)


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
            #print("[%d:%d] -> %s" % (begin, end, str(s.content)))

        return Elf(elf, buffer)

    def hmac_sha1(self, pmk, data):
        # Prepare memory
        local_memory = np.array(self.elf.memory, dtype=np.uint8)  # Make copy of memory
        write_memory(local_memory, self.elf.get_symbol_address('fake_pmk'), pmk)
        write_memory(local_memory, self.elf.get_symbol_address('data'), data)

        # Simulate
        results = trace_register_hws(local_memory, self.elf.meta.entrypoint, self.elf.sp, self.elf.get_symbol_address('stop'))
        print_numpy_as_hex(np.array(bytearray(pmk), dtype=np.uint8), label="PMK")
        print_numpy_as_hex(read_memory(local_memory, self.elf.get_symbol_address('fake_ptk'), 64), label="PTK")

        return results

    def plot_hmac_sha1(self, args):
        if not args.key:
            pmk = random_hamming(32, subkey_size=4)  # Generate uniform random Hamming weights of 32-bit values
        else:
            pmk = binascii.unhexlify(args.key)
        data = b"\x00" * 76

        state = X64EmulationState(self.elf)
        state.write_symbol("fake_pmk", pmk)
        state.write_symbol("data", data)
        state.write_register(UC_X86_REG_RSP, self.elf.sp)

        results = []
        for t in range(0, HMACSHA1_NUM_INSTRUCTIONS):
            if t % 10 == 0:
                print("\rt: %d                     " % t, end='')
            prev_state = state.copy()
            emulate(state, self.elf.get_symbol_address('stop'), 1)
            leakage_result = state.get_leakages(prev_state, hamming_distance_sum_leakage, from_memory=False)
            results.append(leakage_result.leakages)

        return results

    def memcpy(self, data, buffer):
        local_memory = np.array(self.elf.memory, dtype=np.uint8)  # Make copy of memory
        write_memory(local_memory, self.elf.get_symbol_address('data'), data)
        write_memory(local_memory, self.elf.get_symbol_address('buffer'), buffer)

        # Simulate
        results = trace_register_hws(local_memory, self.elf.meta.entrypoint, self.elf.sp, self.elf.get_symbol_address('stop'))
        print_numpy_as_hex(read_memory(local_memory, self.elf.get_symbol_address('buffer'), 128), label="Data (after)")

        return results

    def hmac_sha1_keydep(self, skip):
        self.generic_keydep('fake_pmk', 32, 'data', 72, HMACSHA1_NUM_INSTRUCTIONS, HMACSHA1_NUM_BITFLIPS, skip=skip)

    def memcpy_keydep(self, skip):
        self.generic_keydep('data', 128, 'buffer', 128, MEMCPY_NUM_INSTRUCTIONS, MEMCPY_NUM_BITFLIPS, skip=skip)

    def generic_keydep(self, key_symbol_name, key_length, plaintext_symbol_name, plaintext_length, num_instructions, num_bitflips, skip=0):
        key_dependency_graph = DependencyGraph(DependencyGraphKey.KEY, name="Key dependency graph")
        plaintext_dependency_graph = DependencyGraph(DependencyGraphKey.PLAINTEXT, name="Plaintext dependency graph")

        key = b"\x00" * key_length
        plaintext = b"\x00" * plaintext_length

        clean_state = X64EmulationState(self.elf)
        clean_state.write_symbol(key_symbol_name, key)
        clean_state.write_symbol(plaintext_symbol_name, plaintext)
        clean_state.write_register(UC_X86_REG_RSP, self.elf.sp)

        for b in range(0, num_bitflips):
            # Create reference state: this state will contain a key with all bits zero during the execution
            ref_state = clean_state.copy()

            # Create current key state: this state will contain flipped key bits during the execution
            current_key_state = clean_state.copy()
            current_key_state.write_symbol(key_symbol_name, binascii.unhexlify(("%0" + str(key_length*2) + "x") % (1 << b)))

            # Create current plaintext state: this state will contain flipped plaintext bits during the execution
            current_plaintext_state = clean_state.copy()
            current_plaintext_state.write_symbol(plaintext_symbol_name, binascii.unhexlify(("%0" + str(plaintext_length*2) + "x") % (1 << b)))

            # Run <skip> steps
            if skip != 0:
                emulate(ref_state, self.elf.get_symbol_address('stop'), skip)
                emulate(current_key_state, self.elf.get_symbol_address('stop'), skip)
                emulate(current_plaintext_state, self.elf.get_symbol_address('stop'), skip)

            # Emulate for num_instructions steps
            for t in range(1, num_instructions+1-skip):
                if t % 10 == 0:
                    print("\rBitflipped index: %d, t: %d                  " % (b, t), end='')
                # Progress reference and current states with 1 step
                emulate(ref_state, self.elf.get_symbol_address('stop'), 1)
                emulate(current_key_state, self.elf.get_symbol_address('stop'), 1)
                emulate(current_plaintext_state, self.elf.get_symbol_address('stop'), 1)

                # Diff states and store result in dependency_graph for time t
                current_key_state.diff(ref_state, b, t, key_dependency_graph)
                current_plaintext_state.diff(ref_state, b, t, plaintext_dependency_graph)

        # Print dependencies
        print(key_dependency_graph)
        print(plaintext_dependency_graph)

        pickle.dump(key_dependency_graph, open('/tmp/key_dependency_graph.p', 'wb'))
        pickle.dump(plaintext_dependency_graph, open('/tmp/plaintext_dependency_graph.p', 'wb'))

    def mutual_information_analysis(self, args):
        if args.elf_type == 'memcpy':
            key_meta = InputMeta("data", 128)
            plaintext_meta = InputMeta("buffer", 128)
            m = MutInfAnalysis(self.elf, key_meta, plaintext_meta, MEMCPY_NUM_INSTRUCTIONS, skip=args.skip)
            m.show()
        elif args.elf_type == 'hmac-sha1':
            key_meta = InputMeta("fake_pmk", 32)
            plaintext_meta = InputMeta("data", 72)
            m = MutInfAnalysis(self.elf, key_meta, plaintext_meta, HMACSHA1_NUM_INSTRUCTIONS, skip=args.skip)
            m.show()


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description='')
    arg_parser.add_argument('elf_path', type=str, help='Path to the ELF to analyze.')
    arg_parser.add_argument('elf_type', type=str, choices=['hmac-sha1', 'memcpy'], help='Algorithm that the ELF is executing.')
    arg_parser.add_argument('dataset_path', nargs='?', type=str, default=None, help='Path to store the simulated traces in.')
    arg_parser.add_argument('--num-traces', type=int, default=12800, help='Number of traces to simulate.')
    arg_parser.add_argument('--online-ip', default=None, type=str, help='IP address to stream to.')
    arg_parser.add_argument('--keydep', default=False, action='store_true', help='Create key dependency graph.')
    arg_parser.add_argument('--key', type=str, default=None, help='Hex stream fixed key to use.')
    arg_parser.add_argument('--skip', type=int, default=0, help='Steps to skip in time.')
    arg_parser.add_argument('--mi', default=False, action='store_true', help='Mutual information analysis.')
    args, _ = arg_parser.parse_known_args()

    test_key = b"\xf8\x6b\xff\xcd\xaf\x20\xd2\x44\x4f\x5d\x36\x61\x26\xdb\xb7\x5e\xf2\x4a\xba\x28\xe2\x18\xd3\x19\xbc\xec\x7b\x87\x52\x8a\x4c\x61"

    keys = []
    plaintexts = []
    ciphertexts = []
    trace_set = []

    e = ElectricUnicorn(args.elf_path, dataset_path=args.dataset_path)
    client = None
    if args.online_ip is not None:
        from emcap_online_client import EMCapOnlineClient
        client = EMCapOnlineClient()
        client.connect(args.online_ip)

    if args.mi:
        e.mutual_information_analysis(args)
        exit(0)

    for i in range(0, args.num_traces):
        #pmk = b"\x00\x00" + random_uniform(1) + b"\x00"*29
        #pmk = random_uniform(32)
        results = None
        if args.elf_type == 'hmac-sha1':
            if not args.keydep:
                if not args.key:
                    pmk = random_hamming(32, subkey_size=4)  # Generate uniform random Hamming weights of 32-bit values
                else:
                    pmk = binascii.unhexlify(args.key)
                data = b"\x00" * 76
                results = e.hmac_sha1(pmk=pmk, data=data)

                # results = e.plot_hmac_sha1(args)
            else:
                results = e.hmac_sha1_keydep(skip=args.skip)
        elif args.elf_type == 'memcpy':
            if not args.keydep:
                data_to_copy = random_hamming(128, subkey_size=1)
                buffer = b"\x00"*128
                #buffer = random_hamming(128, subkey_size=1)
                results = e.memcpy(buffer=buffer, data=data_to_copy)
            else:
                results = e.memcpy_keydep(skip=args.skip)

        if args.keydep:
            print("Done keydep")
            exit(0)

        if args.dataset_path is None:
            if args.online_ip is None:
                plt.plot(results)
                plt.show()
                continue

        if args.elf_type == 'hmac-sha1':
            plaintexts.append(bytearray(data))
            keys.append(bytearray(pmk))
        elif args.elf_type == 'memcpy':
            plaintexts.append(bytearray(buffer))
            keys.append(bytearray(data_to_copy))

        trace_set.append(results.astype(np.float32))

        if len(trace_set) == 256:
            assert (len(trace_set) == len(keys))
            np_trace_set = np.array(trace_set)
            np_plaintexts = np.array(plaintexts, dtype=np.uint8)
            np_keys = np.array(keys, dtype=np.uint8)

            if args.online_ip is None:  # Store to file
                filename = str(datetime.utcnow()).replace(" ", "_").replace(".", "_")
                np.save(os.path.join(args.dataset_path, "%s_traces.npy" % filename), np_trace_set)
                np.save(os.path.join(args.dataset_path, "%s_textin.npy" % filename), np_plaintexts)
                np.save(os.path.join(args.dataset_path, "%s_knownkey.npy" % filename), np_keys)
            else:
                client.send(np_trace_set, np_plaintexts, None, np_keys, None)

            keys = []
            plaintexts = []
            ciphertexts = []
            trace_set = []

