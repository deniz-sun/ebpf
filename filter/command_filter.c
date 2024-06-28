#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_CMD_LEN 256
#define FILTER_CMD "ls"

struct bpf_map_def SEC("maps") cmdmap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = MAX_CMD_LEN,
    .max_entries = 128,
};

SEC("kprobe/__x64_sys_execve")
int execve_hook(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    char cmd[MAX_CMD_LEN] = {};
    const char __user *filename = (const char __user *)PT_REGS_PARM1(ctx);

    bpf_probe_read_user(&cmd, sizeof(cmd), filename);
    bpf_map_update_elem(&cmdmap, &pid, &cmd, BPF_ANY);

    // Check if the command matches the filter
    if (strncmp(cmd, FILTER_CMD, sizeof(FILTER_CMD) - 1) == 0) {
        // Prevent execution
        return -1;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";