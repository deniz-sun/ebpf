#include <bpf/libbpf.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
#include <fcntl.h>

#ifndef IS_ERR
#define IS_ERR(ptr) ((unsigned long)(ptr) >= (unsigned long)-4095)
#endif

#ifndef PTR_ERR
#define PTR_ERR(ptr) ((int)(long)(ptr))
#endif

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int prog_fd;
    char filename[] = "bashreadline.bpf.o";
    int ret;

    // Increase RLIMIT_MEMLOCK for loading BPF programs
    struct rlimit rlim_new = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }

    ret = bpf_prog_load(filename, BPF_PROG_TYPE_KPROBE, &obj, &prog_fd);
    if (ret) {
        fprintf(stderr, "Error loading BPF program: %s\n", strerror(-ret));
        return 1;
    }

    prog = bpf_object__find_program_by_title(obj, "uretprobe//bin/bash:readline");
    if (!prog) {
        fprintf(stderr, "Could not find BPF program in object\n");
        return 1;
    }

    link = bpf_program__attach(prog);
    if (IS_ERR(link)) {
        fprintf(stderr, "Error attaching BPF program: %d\n", PTR_ERR(link));
        bpf_object__unload(obj);
        return 1;
    }

    printf("BPF program loaded and attached successfully\n");

    // Open trace_pipe
    int trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY);
    if (trace_fd < 0) {
        perror("Failed to open trace_pipe");
        return 1;
    }

    printf("Reading trace_pipe...\n");

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
