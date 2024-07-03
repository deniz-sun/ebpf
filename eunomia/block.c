/**
* Title: Block
* Author : Deniz Sun
* Description : This eBPF program captures shell processes and the commands they execute. It is used to block certain commands from being executed by shell processes.
*/

#define __TARGET_ARCH_x86
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/sched.h>
#include <linux/limits.h>

#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

// example commands to block
const char prohibited_commands[3][16] = {"ps", "top", "ifconfig"};
#define NUM_PROHIBITED_COMMANDS 3

// types of shells to detect
const char shell_names[2][16] = {"bash", "zsh"};
#define NUM_SHELL_NAMES 2

struct execve_args {
    __u64 syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

// Map to store the command read by readline
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[MAX_LINE_SIZE]);
} command_map SEC(".maps");

// Map to store shell processes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1024);
} shell_processes SEC(".maps");


/*
    * Compare two strings lexicographically
    * Returns:
    *  0 if the strings are equal
    * -1 if str1 is lexicographically less than str2
    *  1 if str1 is lexicographically greater than str2
    
*/
static __always_inline int strings_compare(const char *str1, const char *str2) {
    int i = 0;
    for (; str1[i] != '\0' && str2[i] != '\0'; ++i) {
        if (str1[i] != str2[i]) {
            return str1[i] < str2[i] ? -1 : 1;
        }
    }
    if (str1[i] == '\0' && str2[i] == '\0') {
        return 0; // Both strings are equal
    } else {
        return str1[i] == '\0' ? -1 : 1; // One string is a prefix of the other
    }
}

/*
    * Uprobe to capture the command read by readline
    * The command is stored in the command_map
*/
SEC("uretprobe//bin/bash:readline")
int BPF_KRETPROBE(readline_hook, const void *ret) {
    char str[MAX_LINE_SIZE];
    char comm[TASK_COMM_LEN];
    __u32 key = 0;

    if (!ret)
        return 0;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_probe_read_user_str(str, sizeof(str), ret);

    bpf_printk("Readline captured: %s\n", str);

    bpf_map_update_elem(&command_map, &key, str, BPF_ANY);

    return 0;
}

/*
    * Tracepoint to intercept execve system calls
*/
SEC("tracepoint/syscalls/sys_enter_execve")
int on_execve(struct execve_args *ctx) {
    char comm[TASK_COMM_LEN];
    char *str;
    __u32 pid;
    __u32 key = 0;
    int i;

  //  bpf_printk("Intercepting execve\n");

    bpf_get_current_comm(&comm, sizeof(comm));
    pid = bpf_get_current_pid_tgid() >> 32;


    str = bpf_map_lookup_elem(&command_map, &key);
    if (!str) {
        bpf_printk("Command map lookup failed\n");
        return 0;
    }

//    bpf_printk("Command: %s\n", str);

    // Check if the current process is a shell
    for (i = 0; i < NUM_SHELL_NAMES; i++) {
        if (strings_compare(comm, shell_names[i]) == 0) {
            __u32 value = 1;
            bpf_map_update_elem(&shell_processes, &pid, &value, BPF_ANY);
            bpf_printk("Shell process detected: %s (pid: %d)\n", comm, pid);
            break;
        }
    }

    // Check if the parent process is a shell by looking it up in the map
    __u64 ppid_tgid = bpf_get_current_pid_tgid();
    __u32 ppid = ppid_tgid >> 32;

    __u32 *is_shell = bpf_map_lookup_elem(&shell_processes, &ppid);
    
    //bpf_printk("is shell: %d\n", is_shell);
    //bpf_printk("Command issss: %s\n", str);
    if (is_shell) {
        // Check the command and its arguments
        // bpf_printk("inside the shell check\n");
        for (i = 0; i < NUM_PROHIBITED_COMMANDS; i++) {
            if (strings_compare(str, prohibited_commands[i]) == 0) {
                bpf_printk("Blocked command: %s by %s\n", str, comm);
                return -1; // Block the command by returning an error
            }
        }
        bpf_printk("Allowed command: %s by %s\n", str, comm);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
