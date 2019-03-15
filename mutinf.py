import binascii
import numpy as np
from emulationstate import X64EmulationState
from unicorn.x86_const import *
from electricunicorn import emulate
from inputs import InputMeta
from util import random_uniform, print_numpy_as_hex
from dependencygraph import DependencyGraph, DependencyGraphKey


class MutInfAnalysis:
    def __init__(self, elf, key_meta: InputMeta, plaintext_meta: InputMeta, num_instructions: int):
        self.elf = elf
        self.key_meta = key_meta
        self.plaintext_meta = plaintext_meta
        self.num_instructions = num_instructions

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

    def show(self):
        self.check_whether_random_plaintexts_affect_key_dependencies()
