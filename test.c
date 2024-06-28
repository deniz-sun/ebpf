#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/do_sys_open")
int bpf_prog1(struct pt_regs *ctx) {
        bpf_printk("bpf_prog1 is running\n");

    return 0;
}

char _license[] SEC("license") = "GPL";