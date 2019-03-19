import numpy as np
cimport numpy as np
from unicorn.x86_const import UC_X86_REG_RIP

cdef extern from "inttypes.h":
    ctypedef unsigned long uint64_t
    ctypedef unsigned char uint8_t
    ctypedef unsigned short uint16_t

cdef extern from "simulate.h":
    cdef uint64_t run_trace_register_hws(uint16_t* results, uint8_t* memory, uint64_t memory_size, uint64_t* registers, uint64_t registers_size, uint64_t entrypoint, uint64_t stop_addr);
    cdef uint64_t run_emulation(uint8_t* memory, uint64_t memory_size, uint64_t* registers, uint64_t registers_size, uint64_t entrypoint, uint64_t stop_addr, uint64_t max_instructions);

def trace_register_hws(state, stop_addr):
    max_result_bytes = 1024*1024*10  # 10 MB
    max_results_size = int(max_result_bytes / np.ushort().nbytes)
    cdef np.ndarray[np.uint16_t, ndim=1] results = np.zeros(max_results_size, dtype=np.ushort)

    memory_size = len(state.memory)
    registers_size = len(state.registers)
    cdef np.ndarray[np.uint8_t, ndim=1] cmemory = state.memory
    cdef np.ndarray[np.uint64_t, ndim=1] cregisters = state.registers

    n_instructions = run_trace_register_hws(<uint16_t *>results.data, <uint8_t *>cmemory.data, memory_size, <uint64_t *>cregisters.data, registers_size, state.ip.value, stop_addr)
    results.resize(n_instructions, refcheck=False)

    return results

def emulate(state, stop_addr, max_instructions, reset_entrypoint=False):
    memory_size = len(state.memory)
    registers_size = len(state.registers)
    cdef np.ndarray[np.uint8_t, ndim=1] cmemory = state.memory
    cdef np.ndarray[np.uint64_t, ndim=1] cregisters = state.registers

    run_emulation(<uint8_t *>cmemory.data, memory_size, <uint64_t *>cregisters.data, registers_size, state.ip.value, stop_addr, max_instructions)

    if not reset_entrypoint:  # Do not reset the entrypoint to beginning of program, but save current RIP to it
        state.ip.value = state.registers[UC_X86_REG_RIP]
    state.step_count += 1
