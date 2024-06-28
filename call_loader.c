#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>

#define OBJECT_PATH "/sys/fs/bpf/call_program"
#define BPF_FILENAME "call.o"

int main() {
    struct bpf_object *obj;
    int prog_fd;

    // Load BPF object file
    obj = bpf_object__open_file(BPF_FILENAME, NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object file\n");
        return 1;
    }

    // Load BPF programs from the object
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object file: %s\n", strerror(errno));
        return 1;
    }

    // Attach program to uprobe
    prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "printret"));
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to find BPF program 'printret'\n");
        return 1;
    }
    if (bpf_program__attach_uprobe(prog_fd, -1, OBJECT_PATH, "bin/bash:readline")) {
        fprintf(stderr, "Failed to attach uprobe 'printret': %s\n", strerror(errno));
        return 1;
    }

    printf("eBPF program loaded and attached to uprobe successfully.\n");

    // Clean up
    bpf_object__close(obj);

    return 0;
}
