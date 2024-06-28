CLANG = clang
EXECABLE = monitor-exec
BPFCODE = one
BPFTOOLS = /kernel-src/samples/bpf
BPFLOADER = $(BPFTOOLS)/bpf_load.c

INCLUDE += -I/kernel-src/samples/bpf
INCLUDE += -I/kernel-src/tools/lib

CCINCLUDE += -I/kernel-src/tools/testing/selftests/bpf
CCINCLUDE += -I/kernel-src/tools/lib/bpf
CCINCLUDE += ${INCLUDE}

LOADINCLUDE += -I/kernel-src/tools/include
LOADINCLUDE += -I/kernel-src/tools/perf
LOADINCLUDE += ${INCLUDE}

LIBRARY_PATH = -L/usr/local/lib64
BPFSO = -lbpf

.PHONY: clean bpfload build

clean:
    rm -f *.o *.so $(EXECABLE)

build: ${BPFCODE.c} ${BPFLOADER}
    $(CLANG) -O2 -DHAVE_ATTR_TEST=0 -target bpf -c $(BPFCODE:=.c) $(CCINCLUDE) -o $(BPFCODE:=.o)

bpfload: build
    $(CLANG) -o $(EXECABLE) -DHAVE_ATTR_TEST=0 -lelf $(LOADINCLUDE) $(LIBRARY_PATH) $(BPFSO) \
        $(BPFLOADER) loader.c

$(EXECABLE): bpfload

.DEFAULT_GOAL := $(EXECABLE)
