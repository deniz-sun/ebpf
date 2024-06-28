#include <bpf/libbpf.h>
#include "libbpf/include/linux/err.h"
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
   struct bpf_object *obj;
   struct bpf_program *prog;
   struct bpf_link *link;
   int prog_fd;
   char filename[] = "track.o";
   int ret;

   ret = bpf_prog_load(filename, BPF_PROG_TYPE_TRACEPOINT, &obj, &prog_fd);
   if (ret) {
       fprintf(stderr, "Error loading BPF program: %s\n", strerror(-ret));
       return 1;
   }

   prog = bpf_object__find_program_by_title(obj, "tp/syscalls/sys_enter_execve");
   if (!prog) {
       fprintf(stderr, "Could not find BPF program in object\n");
       return 1;
   }

   link = bpf_program__attach(prog);
   if (IS_ERR(link)) {
       fprintf(stderr, "Error attaching BPF program: %s\n", strerror(PTR_ERR(link)));
       bpf_object__unload(obj);
       return 1;
   }

   printf("BPF program loaded and attached successfully\n");

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