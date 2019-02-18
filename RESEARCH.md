# Electric Unicorn

## Notes
GOT is still used for functions like strlen and memcpy because the dynamic loader replaces these functions with

Goeie resource: https://stackoverflow.com/questions/43367427/32-bit-absolute-addresses-no-longer-allowed-in-x86-64-linux
- `-fno-plt`: Early binding ipv lazy dynamic linking. Verwijdert plt trampoline; sneller voor programma's die veel library calls maken.

## Tutorial

To run:
- Run `compile_cython.sh`
- Run `make clean && make`
- Run `electric_unicorn.py`
