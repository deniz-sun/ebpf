#include <bpf/libbpf.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <errno.h>

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int prog_fd;
    char filename[] = "prog.o";
    int ret;

    // Increase RLIMIT_MEMLOCK for loading BPF programs
    struct rlimit rlim_new = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }

    ret = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
    if (ret) {
        fprintf(stderr, "Error loading BPF program: %s\n", strerror(-ret));
        return 1;
    }

    prog = bpf_object__find_program_by_title(obj, "xdp");
    if (!prog) {
        fprintf(stderr, "Could not find BPF program in object\n");
        return 1;
    }

    link = bpf_program__attach_xdp(prog, "enp0s3");
    if (!link) {
        fprintf(stderr, "Error attaching XDP program to interface: %s\n", strerror(errno));
        bpf_object__unload(obj);
        return 1;
    }

    printf("XDP program loaded and attached successfully\n");

    // Reading trace pipe
    int trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY);
    if (trace_fd < 0) {
        perror("Failed to open trace_pipe");
        return 1;
    }

    printf("eBPF program attached. Reading trace_pipe...\n");

    char buf[4096];
    ssize_t nbytes;
    while ((nbytes = read(trace_fd, buf, sizeof(buf) - 1)) > 0) {
        buf[nbytes] = '\0';
        printf("%s", buf);
    }

    close(trace_fd);

    bpf_link__destroy(link);
    bpf_object__unload(obj);
    return 0;
}
