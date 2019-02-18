cimport numpy as np

cdef extern from "inttypes.h":
    ctypedef long uint64_t
    ctypedef unsigned char uint8_t
    ctypedef unsigned short uint16_t

cdef extern from "simulate.h":
    cdef uint64_t run_trace_register_hws(uint16_t* results, uint8_t* memory, uint64_t memory_size, uint64_t entrypoint, uint64_t sp, uint64_t pmk, uint64_t ptk, uint64_t stop_addr);

def trace_register_hws(np.ndarray[np.uint16_t, ndim=1] results, bytearray memory, int memory_size, entrypoint, sp, pmk, ptk, stop_addr):
    n_instructions = run_trace_register_hws(<uint16_t *>results.data, memory, memory_size, entrypoint, sp, pmk, ptk, stop_addr)
    results.resize(n_instructions, refcheck=False)