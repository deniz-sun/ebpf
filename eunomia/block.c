#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <linux/sched.h>
#include <linux/limits.h>

#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

const char prohibited_commands[3][16] = {"ps", "top", "ifconfig"};
#define NUM_PROHIBITED_COMMANDS 3

const char shell_names[3][16] = {"bash", "sh", "zsh"};
#define NUM_SHELL_NAMES 3

struct execve_args {
    __u64 syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[MAX_LINE_SIZE]);
} filename_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1024);
} shell_processes SEC(".maps");


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

SEC("tracepoint/syscalls/sys_enter_execve")
int on_execve(struct execve_args *ctx) {
    char comm[TASK_COMM_LEN];
    __u32 pid;
    int i;

    bpf_printk("Intercepting execve\n");

    bpf_get_current_comm(&comm, sizeof(comm));
    pid = bpf_get_current_pid_tgid() >> 32;

    // Use per-CPU array map for filename
    __u32 key = 0;

    
    char *filename = bpf_map_lookup_elem(&filename_map, &key);
    bpf_printk("Filename: %s\n", filename);
    if (!filename) {
        bpf_printk("Filename map lookup failed\n");
        return 0;
    }
    bpf_probe_read_user_str(filename, MAX_LINE_SIZE, ctx->filename);

    bpf_printk("Command: %s Filename: %s PID: %d\n", comm, filename, pid);

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

    if (is_shell) {
        // Check the command and its arguments
        for (i = 0; i < NUM_PROHIBITED_COMMANDS; i++) {
            if (strings_compare(filename, prohibited_commands[i]) == 0) {
                bpf_printk("Blocked command: %s by %s (pid: %d)\n", filename, comm, pid);
                return -1; // Block the command by returning an error
            }

            // Check command line arguments
             const char **argv = ctx->argv;
            #pragma unroll
            for (int j = 1; j < 5; j++) {
                char arg[MAX_LINE_SIZE];
                bpf_probe_read_user(&arg, sizeof(arg), argv + j);
                if (arg[0] == '\0') break;  // Stop if the argument is empty
                if (strings_compare(arg, prohibited_commands[i]) == 0) {
                    bpf_printk("Blocked command argument: %s by %s (pid: %d)\n", arg, comm, pid);
                    return -1; // Block the command by returning an error
                }
            }
        }
        bpf_printk("Allowed command: %s by %s (pid: %d)\n", filename, comm, pid);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
