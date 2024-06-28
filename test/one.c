#include <errno.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <string.h>


#include "libbpf.h"

#define SEC(NAME) __attribute__((section(NAME), used))

SEC("kprobe/execve")
int bpf_prog1(struct pt_regs *ctx)
{
        char m[]="hello world";
        bpf_trace_printk(m,sizeof(m));
        
        return 0;
}

char _license[] SEC("license") = "GPL";