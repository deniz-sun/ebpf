#define __TARGET_ARCH_x86
#define TASK_COMM_LEN 16
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/sched.h>

SEC("kprobe/sys_execve")
int BPF_KPROBE(execve_entry, const char *filename, const char *const argv[], const char *const envp[])
{
    bpf_printk("sys_execve called\n");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
