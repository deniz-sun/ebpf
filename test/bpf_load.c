#include <stdio.h>

#include <linux/bpf.h>
#include <sys/resource.h>

int main(int argc, char **argv) {
    if (load_bpf_file("one.o")) {
        printf("%s", "entered if block\n");
        return 1;
    }
    return 0;
}