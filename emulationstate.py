import numpy as np
from unicorn.x86_const import *
from util import EUException, Ref, diff_numpy_arrays
from collections import namedtuple

LeakageResult = namedtuple("LeakageResult", ["old", "new", "indices", "leakages", "is_memory", "rip"])


class X64EmulationState:
    def __init__(self, elf=None):
        if elf is not None:
            self.memory = np.array(elf.memory, dtype=np.uint8)
            self.registers = np.zeros(UC_X86_REG_ENDING-1, dtype=np.uint64)  # Do not include UC_X86_REG_ENDING -- weird stuff will happen
            self.elf = elf
            self.ip = Ref(self.elf.meta.entrypoint)
        else:
            self.memory = None
            self.registers = None
            self.elf = None
            self.ip = None

    def write_symbol(self, symbol_name, data: bytes):
        self.write_memory(self.elf.get_symbol_address(symbol_name), data)

    def read_memory(self, address, length):
        return self.memory[address:address + length]

    def write_memory(self, address, data: bytes):
        self.memory[address:address+len(data)] = bytearray(data)

    def read_register(self, register):
        return self.registers[register]

    def write_register(self, register, value):
        self.registers[register] = value

    def copy(self):
        new = X64EmulationState()
        new.memory = np.copy(self.memory)
        new.registers = np.copy(self.registers)
        new.elf = self.elf
        new.ip = Ref(self.ip.value)
        return new

    def diff(self, other_state, b, t, dependency_graph, registers_only=False, skip_dup=True):
        if len(other_state.memory) != len(self.memory):
            raise EUException("Cannot diff memories of different sizes")
        if len(other_state.registers) != len(self.registers):
            raise EUException("Cannot diff registers of different sizes")

        if not registers_only:
            # Vectorized approach (faster)
            ind_mem = np.arange(len(self.memory))
            diff_mem = (self.memory - other_state.memory) != 0
            select_mem = self.memory[diff_mem]
            select_ind = ind_mem[diff_mem]
            for i in range(len(select_mem)):
                dependency_graph.update(select_ind[i], b, t, select_mem[i], skip_dup=skip_dup)

        # TODO dup code
        ind_reg = np.arange(len(self.registers))
        diff_reg = (self.registers - other_state.registers) != 0
        select_reg = self.registers[diff_reg]
        select_ind = ind_reg[diff_reg]
        for i in range(len(select_reg)):
            dependency_graph.update(select_ind[i], b, t, select_reg[i], is_register=True, skip_dup=skip_dup)

    def get_leakages(self, previous_state, leakage_function, from_memory=False):
        rip = self.registers[UC_X86_REG_RIP]

        if from_memory:
            prev_mem, new_mem, addresses = diff_numpy_arrays(previous_state.memory, self.memory)
            leakages = leakage_function(prev_mem, new_mem)
            return LeakageResult(old=prev_mem, new=new_mem, indices=addresses, leakages=leakages, is_memory=True, rip=rip)
        else:
            prev_reg, new_reg, registers = diff_numpy_arrays(previous_state.registers, self.registers)
            leakages = leakage_function(prev_reg, new_reg)
            return LeakageResult(old=prev_reg, new=new_reg, indices=registers, leakages=leakages, is_memory=False, rip=rip)

    def __repr__(self):
        result = "Memory:\n"
        result += str(self.memory)
        result += "\nRegisters:\n"
        result += str(self.registers)
        return result
