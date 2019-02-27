import numpy as np
cimport numpy as np

cdef extern from "inttypes.h":
    ctypedef long uint64_t
    ctypedef unsigned char uint8_t
    ctypedef unsigned short uint16_t

cdef extern from "simulate.h":
    cdef uint64_t run_trace_register_hws(uint16_t* results, uint8_t* memory, uint64_t memory_size, uint64_t entrypoint, uint64_t sp, uint64_t stop_addr);
    cdef uint64_t run_emulation(uint8_t* memory, uint64_t memory_size, uint64_t entrypoint, uint64_t sp, uint64_t stop_addr, uint64_t max_instructions);

def trace_register_hws(memory, entrypoint, sp, stop_addr):
    max_result_bytes = 1024*1024*1024
    memory_size = len(memory)
    cdef np.ndarray[np.uint16_t, ndim=1] results = np.zeros(int(max_result_bytes / np.ushort().nbytes), dtype=np.ushort)
    cdef np.ndarray[np.uint8_t, ndim=1] cmemory = memory

    n_instructions = run_trace_register_hws(<uint16_t *>results.data, <uint8_t *>cmemory.data, memory_size, entrypoint, sp, stop_addr)
    results.resize(n_instructions, refcheck=False)

    return results

def emulate(memory, entrypoint, sp, stop_addr, max_instructions):
    memory_size = len(memory)
    cdef np.ndarray[np.uint8_t, ndim=1] cmemory = memory

    n_instructions = run_emulation(<uint8_t *>cmemory.data, memory_size, entrypoint, sp, stop_addr, max_instructions)