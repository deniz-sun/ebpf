#include <linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>

SEC("tp/syscalls/sys_enter_execve")
int detect_execve() {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // Get the PID of the current process
    unsigned long pid_tgid = bpf_get_current_pid_tgid();
    unsigned int pid = pid_tgid >> 32;

    // Print the PID and the command name
    bpf_printk("PID: %u Command: %s\n", pid, comm);

    return 0;
}

char _license[] SEC("license") = "GPL";