# Electric Unicorn

## Notes
GOT is still used for functions like strlen and memcpy because the dynamic loader replaces these functions with

Goeie resource: https://stackoverflow.com/questions/43367427/32-bit-absolute-addresses-no-longer-allowed-in-x86-64-linux
- `-fno-plt`: Early binding ipv lazy dynamic linking. Verwijdert plt trampoline; sneller voor programma's die veel library calls maken.

## Memory tracking pseudocode

Idee 1: fail
- Keep list of marked addresses / registers that are of interest and store memory + register state.
- On read or write from these addresses / registers, check which registers change and mark them. Marking also adds the register

Idee 2: Tombala
For each instruction / time step t:
    - Set key = 0, attacker-controlled data = 0
    - Store full memory + registers state of program (= clean state)
    - Execute instruction up to time = t-1 and store full memory + registers state (= reference state)
    - Rewind to clean state
    For i in 0..128 (num_key_bits):
        - Set key = 1 << i (flip one bit)
        - Execute instruction up to time = t and store full memory + registers state (= current state)
        - Diff current state and reference state. Store the addresses, registers that changed (if any) together with the instruction (Capstone) in a list (key_bit_list) for time = t and bit i.
        - Rewind to clean state
    - Optional: take the union of all changes for time = t in key_bit_list (if considering multiple bits)
    For i in 0..128 (num_attacker_bits):
        - Set attacker-controlled data = 0
        - Execute instruction up to time = t and store full memory + registers state (= current state)
        - Diff current state and reference state. Store the addresses, registers that changed (if any) together with the instruction (Capstone) in a list (data_bit_list) for time = t and bit i.
        - If a change is present for bit i in both the data_bit_list, and key_bit list, store the bit in the both_bit_list for time = t
        - Rewind to clean state
    - Optional: take the union of all changes for time = t in data_bit_list (if considering multiple bits)
    - Optional: take the union of all changes for time = t in both_bit_list (if considering multiple bits)


## Tutorial

To run:
- Run `compile_cython.sh`
- Run `make clean && make`
- Run `electric_unicorn.py`
