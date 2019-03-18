import binascii
import numpy as np
import pickle
from emulationstate import X64EmulationState
from unicorn.x86_const import *
from electricunicorn import emulate
from inputs import InputMeta
from util import random_uniform, print_numpy_as_hex
from dependencygraph import DependencyGraph, DependencyGraphKey
from collections import defaultdict, namedtuple
from x86_const_enum import X86ConstEnum

Observation = namedtuple("Observation", ["time", "key_bit", "value", "origin"])


def calc_mi(observations):
    X = set([o.key_bit for o in observations])
    Y = set([o.value for o in observations])
    mi = 0
    for x in X:
        px = len([o for o in observations if o.key_bit is x]) / len(observations)
        for y in Y:
            py = len([o for o in observations if o.value == y]) / len(observations)
            pxy = len([o for o in observations if (o.key_bit == x and o.value == y)]) / len(observations)
            if pxy != 0:
                mi += pxy * np.log2(pxy / (px * py))
    return mi


class MutInfAnalysis:
    def __init__(self, elf, key_meta: InputMeta, plaintext_meta: InputMeta, num_instructions: int, skip: int):
        self.elf = elf
        self.key_meta = key_meta
        self.plaintext_meta = plaintext_meta
        self.num_instructions = num_instructions
        self.skip = skip

    def check_whether_random_plaintexts_affect_key_dependencies(self, n=10):
        """
        Test function that checks whether we can determine the key dependencies in a pre-processing step when assuming
        that the plaintext is constant. This is checked by observing whether the key dependencies change if the plain-
        text is changed in a random manner.
        :return:
        """
        tested = set()
        static_pt_dependency_graph = DependencyGraph(DependencyGraphKey.KEY, name="Static-plaintext key dependency graph")
        dynamic_pt_dependency_graph = DependencyGraph(DependencyGraphKey.KEY, name="Dynamic-plaintext key dependency graph")
        zero_key = b"\x00" * self.key_meta.length
        zero_plaintext = b"\x00" * self.plaintext_meta.length

        clean_state = X64EmulationState(self.elf)
        clean_state.write_symbol(self.key_meta.symbol_name, zero_key)
        clean_state.write_symbol(self.plaintext_meta.symbol_name, zero_plaintext)
        clean_state.write_register(UC_X86_REG_RSP, self.elf.sp)

        # Create reference state: this state will contain a key with all bits zero during the execution
        ref_state = clean_state.copy()
        emulate(ref_state, self.elf.get_symbol_address('stop'), self.num_instructions)

        for b in range(0, self.key_meta.length*8):
            key = binascii.unhexlify(("%0" + str(self.key_meta.length * 2) + "x") % (1 << b))
            dyn_pt = random_uniform(self.plaintext_meta.length)

            # Flip bit of key but keep static plaintext
            static_pt_state = clean_state.copy()
            static_pt_state.write_symbol(self.key_meta.symbol_name, key)
            # Emulate and diff
            emulate(static_pt_state, self.elf.get_symbol_address('stop'), self.num_instructions)
            static_pt_state.diff(ref_state, b, 0, static_pt_dependency_graph)

            # Flip bit of key but also change plaintext
            dyn_pt_state = clean_state.copy()
            dyn_pt_state.write_symbol(self.key_meta.symbol_name, key)
            dyn_pt_state.write_symbol(self.plaintext_meta.symbol_name, dyn_pt)
            # Emulate and diff
            emulate(dyn_pt_state, self.elf.get_symbol_address('stop'), self.num_instructions)
            dyn_pt_state.diff(ref_state, b, 0, dynamic_pt_dependency_graph)

            eq = static_pt_dependency_graph.has_same_deps(dynamic_pt_dependency_graph)
            if eq is False:
                print("-------Found not equal at bit %d:" % b)
                print_numpy_as_hex(np.array(bytearray(key)), "Key")
                print_numpy_as_hex(np.array(bytearray(dyn_pt)), "Plaintext")

            tested.add((key, dyn_pt))
        print("Tested:")
        print(tested)
        print("Done!")

    def analyze(self, random_samples_per_bit=32):
        zero_key = b"\x00" * self.key_meta.length
        zero_plaintext = b"\x00" * self.plaintext_meta.length

        clean_state = X64EmulationState(self.elf)
        clean_state.write_symbol(self.key_meta.symbol_name, zero_key)
        clean_state.write_symbol(self.plaintext_meta.symbol_name, zero_plaintext)
        clean_state.write_register(UC_X86_REG_RSP, self.elf.sp)

        #for b in range(0, self.key_meta.length*8):
        for b in range(0, 1):
            observations = defaultdict(lambda: [])
            for p in range(0, random_samples_per_bit):
                print("\rBit: %d, pt: %d                        " % (b, p), end='')
                # Get a random key and plaintext, but set a certain bit of the key to zero / one
                one_dependency_graph = DependencyGraph(DependencyGraphKey.KEY, name="Key dependency graph (one values)")
                zero_dependency_graph = DependencyGraph(DependencyGraphKey.KEY, name="Key dependency graph (zero values)")
                random_pt = random_uniform(self.plaintext_meta.length)
                random_key = random_uniform(self.key_meta.length)
                mask = np.frombuffer(binascii.unhexlify(("%0" + str(self.key_meta.length * 2) + "x") % (1 << b)), dtype=np.uint8)
                imask = np.bitwise_not(mask)
                random_key_zero = bytes(np.bitwise_and(imask, np.frombuffer(random_key, dtype=np.uint8)).data)
                random_key_one = bytes(np.bitwise_or(mask, np.frombuffer(random_key, dtype=np.uint8)).data)

                # print_numpy_as_hex(mask, "Mask")
                # print_numpy_as_hex(np.frombuffer(random_key_zero, dtype=np.uint8), "Zero")
                # print_numpy_as_hex(np.frombuffer(random_key_one, dtype=np.uint8), "One")

                # Create states
                zero_state = clean_state.copy()
                zero_state.write_symbol(self.key_meta.symbol_name, random_key_zero)
                zero_state.write_symbol(self.plaintext_meta.symbol_name, random_pt)

                one_state = clean_state.copy()
                one_state.write_symbol(self.key_meta.symbol_name, random_key_one)
                one_state.write_symbol(self.plaintext_meta.symbol_name, random_pt)

                # Emulate and store dependencies in key_dependency_graph
                if self.skip != 0:
                    emulate(zero_state, self.elf.get_symbol_address('stop'), self.skip)
                    emulate(one_state, self.elf.get_symbol_address('stop'), self.skip)
                for t in range(1, self.num_instructions+1-self.skip):
                    emulate(zero_state, self.elf.get_symbol_address('stop'), 1)
                    emulate(one_state, self.elf.get_symbol_address('stop'), 1)
                    one_state.diff(zero_state, b, t, one_dependency_graph, skip_dup=True)
                    zero_state.diff(one_state, b, t, zero_dependency_graph, skip_dup=True)

                # Store observations

                # Per bit
                for c in zero_dependency_graph:
                    for t in zero_dependency_graph[c][b]:
                        if type(c) is X86ConstEnum:
                            max_shift = 64
                        else:
                            max_shift = 8
                        for shift in range(0, max_shift):
                            mask = 0x01 << shift
                            o = Observation(time=t, key_bit=0, value=1 if int(zero_dependency_graph[c][b][t]) & mask else 0, origin="%s_%d" % (str(c), shift))
                            observations[t].append(o)
                for c in one_dependency_graph:
                    for t in one_dependency_graph[c][b]:
                        if type(c) is X86ConstEnum:
                            max_shift = 64
                        else:
                            max_shift = 8
                        for shift in range(0, max_shift):
                            mask = 0x01 << shift
                            o = Observation(time=t, key_bit=1, value=1 if int(one_dependency_graph[c][b][t]) & mask else 0, origin="%s_%d" % (str(c), shift))
                            observations[t].append(o)

                """
                # Per byte
                for c in zero_dependency_graph:
                    for t in zero_dependency_graph[c][b]:
                        o = Observation(time=t, key_bit=0, value=zero_dependency_graph[c][b][t], origin="%s" % str(c))
                        observations[t].append(o)
                for c in one_dependency_graph:
                    for t in one_dependency_graph[c][b]:
                        o = Observation(time=t, key_bit=1, value=one_dependency_graph[c][b][t], origin="%s" % str(c))
                        observations[t].append(o)
                """

            print('')
            self.calc_observations_mi(observations)

    def calc_observations_mi(self, observations):
        results = []
        f = open("/tmp/results.txt", "w")
        for t in observations:
            observations_by_origin = defaultdict(lambda: [])
            for o in observations[t]:
                observations_by_origin[o.origin].append(o)
            for origin, o_list in observations_by_origin.items():
                mi = calc_mi(o_list)
                line = "t=%d, origin=%s, mi=%f\n" % (t, origin, mi)
                f.write(line)
                results.append((t, origin, mi))
                print(line, end='')
        f.close()
        with open("/tmp/results.p", "wb") as f:
            pickle.dump(results, f)

    def show(self):
        # self.check_whether_random_plaintexts_affect_key_dependencies()
        self.analyze()

