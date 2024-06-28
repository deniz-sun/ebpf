# ebpf


libbpf needs to be installed.
"sudo apt install libbpf-dev"


## /eunomia
There are eunomia's development tools, "ecc" and "ecli", under this folder. It makes compilation and execution smoother.

To compile a bpf program, run the "ecc" command: ./ecc program.c
This creates a package.json with necessary details, which can then be used to run the program.

To run the bpf program, run the "ecli" command with sudo permission: sudo ./ecli package.json

## clang compilation
"clang -O2 -target bpf -c bpf_program.c -o bpf_program.o"

### Makefile
This compiles the ebpf program, loads and attaches it.
Currently the programs can only compile and load. The attachment part is not successful.

### Loader program
An additional way of running the ebpf program is by using a loader written in C.
Ebpf program is compiled as usual with "clang" and the loader is compiled with gcc with the lbpf flag. This is for linking against libbpf, the library that loads bpf programs into the kernel.
"gcc -o loader loader.c -lbpf"
