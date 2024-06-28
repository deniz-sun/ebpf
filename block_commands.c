#define __TARGET_ARCH_x86
#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/sched.h>

// Define prohibited commands
#define MAX_PROHIBITED_CMDS 2
const char prohibited_cmds[MAX_PROHIBITED_CMDS][MAX_LINE_SIZE] = {"ls", "cat"};

// Custom string comparison function
static __inline int my_strcmp(const char *s1, const char *s2) {
    int i = 0;
    while (s1[i] != '\0' && s2[i] != '\0') {
        if (s1[i] != s2[i]) {
            return -1;
        }
        i++;
    }
    if (s1[i] == '\0' && s2[i] == '\0') {
        return 0;
    }
    return -1;
}

SEC("uretprobe//bin/bash:readline")
int BPF_KRETPROBE(printret, const void *ret)
{
    char str[MAX_LINE_SIZE];
    char comm[TASK_COMM_LEN];
    __u32 pid;

    if (!ret)
        return 0;

    bpf_get_current_comm(&comm, sizeof(comm));

    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_user_str(str, sizeof(str), ret);

    bpf_printk("PID %d (%s) read: %s ", pid, comm, str);

    return 0;
}

SEC("kprobe/sys_execve")
int BPF_KPROBE(execve_entry, const char *filename, const char *const argv[], const char *const envp[])
{
    char comm[TASK_COMM_LEN];
    __u32 pid;

    bpf_get_current_comm(&comm, sizeof(comm));
    pid = bpf_get_current_pid_tgid() >> 32;

    char cmd[MAX_LINE_SIZE];
    long err = bpf_probe_read_user_str(cmd, sizeof(cmd), filename);
    if (err < 0) {
        return 0;
    }

    for (int i = 0; i < MAX_PROHIBITED_CMDS; i++) {
        if (my_strcmp(cmd, prohibited_cmds[i]) == 0) {
            bpf_printk("Blocking command PID %d (%s): %s", pid, comm, cmd);
            return -1; // Block the command
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
