## Table of Contents

1. [Introduction](#introduction)
2. [BPF - Berkeley Packet Filter](#bpf---berkeley-packet-filter)
3. [eBPF - Extended Berkeley Packet Filter](#ebpf---extended-berkeley-packet-filter)
4. [Requirements](#requirements)
5. [BPF Helper Functions](#bpf-helper-functions)
6. [Compilation & Execution with Eunomia’s BPF Framework](#compilation--execution-with-eunomias-bpf-framework)
7. [Compilation and Execution with a Loader Program](#compilation-and-execution-with-a-loader-program)
8. [Monitoring and Blocking Command Line arguments](#monitoring-and-blocking-command-line-arguments)
9. [Helpful Links and Some Example eBPF Projects](#helpful-links-and-some-example-ebpf-projects)
10. [References](#references)

## **Introduction**

This repository contains various eBPF test projects aimed at demonstrating the capabilities and functionalities of the eBPF technology. The projects include examples of packet filtering, function tracing, and command-line monitoring. This README provides detailed instructions on setting up the environment, compiling, and executing the eBPF programs.

## **BPF - Berkeley Packet Filter**

BPF is a type of packet filter that runs in the Linux kernel. BPF is usually used to capture and analyze packets efficiently. For example, tcpdump is used with BPF to quickly filter out irrelevant packets. However BPF is not sufficient for handling HTTP sessions. BPF allows to inspect a payload of individual packets while HTTP sessions compose of multiple TCP packets so it is not enough to handle this filtering.

## **eBPF - Extended Berkeley Packet Filter**

Extended BPF, eBPF, was created for this. eBPF (extended Berkeley Packet Filter) is a revolutionary technology that allows users to run sandboxed programs in the Linux kernel without changing kernel source code or loading kernel modules \[1]. This technology is being used for many purposes such as networking, security, and observability. It allows adding hooks to functions and system calls. This provides visibility into traffic payloads and function results. Hence, it can be used to handle complex functionality such as layer-7 filtering independently of the application sending data to the kernel \[2].


## **Requirements**

### **Prerequisites**

Ensure that you have the following prerequisites before proceeding with the setup:

- Any recent Ubuntu distribution. Ubuntu 22.04 was used for this project.
- Administrative (sudo) access to your system
- Kernel version 4.4 or later.

You can check the kernel version by running

    uname -r


### **Set up**

Step 1: Update your package manager
    
    sudo apt-get update

Step 2: Install necessary build dependencies
    
    sudo apt-get install -y build-essential gcc make libelf-dev clang llvm libnl-genl-3-dev pkg-config

Step 3: Install BCC tools
For Ubuntu, specific instructions are available in the IOVisor project documentation
    
    echo "deb [signed-by=/usr/share/keyrings/iovisor-archive-keyring.gpg] https://repo.iovisor.org/apt/$(lsb_release -cs) $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/iovisor.list
    sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD
    sudo apt-get update
    sudo apt-get install -y bcc-tools libbcc-examples linux-headers-$(uname -r)

Step 4: Install the Linux headers for your current kernel version
    
    sudo apt-get install -y linux-headers-$(uname -r)

Step 5: Clone the libbpf repository

    git clone https://github.com/libbpf/libbpf.git

Step 6: Build libbpf

    cd libbpf/src
    make

Step 7: Install libbpf

    sudo make install
    sudo ldconfig



One particular issue that might be encountered is the following include error.

    In file included from /usr/include/linux/bpf.h:11:

    /usr/include/linux/types.h:5:10: fatal error: 'asm/types.h' file not found

    #include <asm/types.h>

          ^~~~~~~~~~~~~

    1 error generated.

→ Although \<asm/types.h> is not included manually in the code, it comes from the inclusion of \<bpf/bpf.c> and generates the error.

To solve this asm include issue, the following line can be used to link it to the the linux headers.

    sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm

For debugging and monitoring purposes, tools like bpftool, bpftrace and perf can be used.

    sudo apt-get install -y bpftool bpftrace linux-perf


## **BPF Helper Functions**

Since eBPF programs are written in restricted C and compiled into eBPF bytecode, some of the C libraries and functionalities cannot be used. eBPF offers many helper functions for multiple purposes. Some examples can be seen below.

1. **Memory Access Helpers**

   - `bpf_probe_read(): Reads data from an arbitrary memory location.`

   - `bpf_probe_read_user(): Safely reads data from user space.`

   - `bpf_probe_read_kernel(): Safely reads data from kernel space.`

   - `bpf_probe_read_str(): Reads a NULL-terminated string from user space.`

2. **Map Management Helpers**

   - `bpf_map_lookup_elem(): Looks up an element in a BPF map by key.`

   - `bpf_map_update_elem(): Adds or updates a map element by key.`

   - `bpf_map_delete_elem(): Deletes an element from a BPF map by key.`

3. **Packet Manipulation Helpers**

   - `bpf_skb_store_bytes(): Writes data into a packet at a specified offset.`

   - `bpf_l3_csum_replace(): Updates the checksum of a packet after modifying the L3 (network layer) data.`

   - `bpf_l4_csum_replace(): Updates the checksum of a packet after modifying the L4 (transport layer) data.`

4. **Time and Random Numbers**

   - `bpf_ktime_get_ns(): Returns the current kernel time in nanoseconds.`

   - `bpf_get_prandom_u32(): Generates a pseudo-random number.`

5. **Networking Helpers**

   - `bpf_clone_redirect(): Clones the incoming packet and redirects it to another interface.`

   - `bpf_redirect(): Redirects the packet to another interface or CPU.`

6. **Event and Tracepoint Helpers**

   - `bpf_trace_printk(): Prints a formatted message into the trace buffer.`

   - `bpf_perf_event_output(): Writes custom data to a BPF perf event buffer.`

7. **Program Control Helpers**

   - `bpf_tail_call(): Calls another BPF program in a chain of programs.`

   - `bpf_override_return(): Overrides the return value of the hooked function.`

8. **Socket Buffer Helpers**

   - `bpf_skb_adjust_room(): Adjusts the headroom or tailroom of a socket buffer.`

eBPF uses helper macros to place programs, maps and license in different sections in the file. It is defined as “SEC(.....)”. 

Some example helper macros:

- kprobe/do\_sys\_open: Event tracking

- XDP: To receive network packets

- xdp\_drop: Drops data packets

To use certain BPF helpers, it must be licensed under a GPL-compatible license. It is declared with the helper macro as “license”: 

    char LICENSE[] SEC("license") = "GPL";

## **Compilation & Execution with Eunomia’s BPF Framework**

Eunomia offers a compiler and runtime toolchain framework, “eunomia-bpf” [3] with the aim of building and distributing eBPF programs more easily. 

### **Download and Install eunomia-bpf Development Tools**

This subsection information and guide is taken directly from Eunomia’s documentation \[3]. 

Download the ecli tool for running eBPF programs:

    wget https://aka.pw/bpf-ecli -O ecli && chmod +x ./ecli

    ./ecli -h


Download the compiler toolchain for compiling eBPF kernel code into config files or WASM modules:

    wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc && chmod +x ./ecc

    ./ecc -h


Or if Docker is installed, it can also be compiled using the docker image:

    docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest 
    # Compile using docker. `pwd` should contain *.bpf.c files and *.h files.


The following code is a simple eBPF program that captures bash entries and prints whenever something is executed on the command line.

**minimal.bpf.c**

    #define __TARGET_ARCH_x86

    #include <linux/bpf.h>

    #include <linux/ptrace.h>

    #include <bpf/bpf_helpers.h>

    #include <bpf/bpf_tracing.h>

    #include <linux/sched.h>

    #define TASK_COMM_LEN 16

    #define MAX_LINE_SIZE 80

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

    };

    char LICENSE[] SEC("license") = "GPL";

Uprobe is used to capture user space function calls. The uprobe probe is defined using the SEC macro and the probe function is defined using the BPF\_KRETPROBE macro.

“ecc” tool is used to compile a program. It compiles the .c file into an object, then packs the ebpf object and config into package.json. 

    ./ecc minimal.bpf.c

Another way to compile is using a docker image:

    docker run -it -v `pwd`/:/src/ ghcr.io/eunomia-bpf/ecc-`uname -m`:latest

 

"ecli" tool is used to run the compiled program (package.json)

    sudo ./ecli run package.json

### **Tracing**

Linux’s trace pipe can be used to check the output of the eBPF program. Open the trace pipe in another terminal.

    sudo cat /sys/kernel/debug/tracing/trace_pipe

‌

## **Compilation and Execution with a Loader Program**

An additional way of running the eBPF program is by using a loader written in C. The eBPF program is compiled as usual with clang compiler and the loader is compiled with gcc with the lbpf flag. This is for linking against libbpf, the library that loads BPF programs into the kernel. After being linked by the loader program with libbpf in the user space, the eBPF program runs in the kernel space.

The following function will be used to demonstrate this. To track execve calls, the “sys\_enter\_execve” macro can be used. The following sample application retrieves the process ID of the execve system call invocation using the bpf\_get\_current\_pid\_tgid and bpf\_printk functions, and prints it in the kernel log.

**track.c**

    #include <linux/bpf.h>

    #include <linux/version.h>

    #include <bpf/bpf_helpers.h>

    SEC("tp/syscalls/sys_enter_execve")

    int detect_execve() {

       char comm[16];

       bpf_get_current_comm(&comm, sizeof(comm));

       // PID of the current process

       unsigned long pid_tgid = bpf_get_current_pid_tgid();

       unsigned int pid = pid_tgid >> 32;

       // PID and the command name

       bpf_printk("PID: %u Command: %s\n", pid, comm);

       return 0;

    }

    char _license[] SEC("license") = "GPL";

The eBPF program called track.c is compiled using:

    clang -O2 -target bpf -o track.o -c track.c

To load and attach this eBPF program, the following sample loader program can be used. It also opens the trace pipe and prints the output on the console so there is no need to manually open the trace pipe.
**track\_loader.c**

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

This loader in C is compiled by using gcc:

    gcc -o track_loader track_loader.c -lbpf

This compiles the loader into an object which can then be run with sudo permission.

    sudo ./track_loader


## **Monitoring and Blocking Command Line arguments**
This application is for monitoring shell command lines and possibly block unwanted comments. [Work in progress]

The file is located under the /eunomia folder and it is called "block.c".

Compile and run with eunomia-bpf tools
   
    ./ecc block.c
   
    sudo ./ecli run package.json

Open the trace pipe to check the output

    sudo cat /sys/kernel/debug/tracing/trace_pipe
    
Currently the blocking functionality does not stop execution but shell processes and bash commands are detected and printed with the related process id.

## **Helpful Links and Some Example eBPF Projects**

**Bad BPF**

"A collection of malicious eBPF programs that make use of eBPF's ability to read and write user data in between the usermode program and the kernel [4]."
This repository features maliciously intented eBPF programs that can be altered to use for security purposes.


**BPF Time**

bpftime, a full-featured, high-performance eBPF runtime designed to operate in userspace. It offers fast Uprobe and Syscall hook capabilities: Userspace uprobe can be 10x faster than kernel uprobe and can programmatically hook all syscalls of a process safely and efficiently [5].


**Packet Filtering Firewall**

This is a packet filtering firewall project that uses eBPF to offer a flexible and powerful way of protecting netwrok from bad actors [6]. 


## **References**

\[1] “What is eBPF? An Introduction and Deep Dive into the eBPF Technology,” _www\.ebpf.io_. <https://ebpf.io/what-is-ebpf/> (accessed Jun. 24, 2024).

\[2] Datadog, “A practical guide to capturing production traffic with eBPF,” _Datadog_, Nov. 10, 2022. https\://www\.datadoghq.com/blog/ebpf-guide/ (accessed Jun. 24, 2024).

\[3] “eBPF Tutorial by Example 1: Hello World, Framework and Development - eunomia,” _eunomia.dev_. https\://eunomia.dev/tutorials/1-helloworld/ (accessed Jul. 02, 2024).

\[4] “pathtofile/bad-bpf,” https://github.com/pathtofile/bad-bpf?tab=readme-ov-file#write-blocker (accessed Jul. 03, 2024).

\[5] “bpftime: Userspace eBPF runtime for fast Uprobe & Syscall Hook & Extensions - eunomia,” eunomia.dev. https://eunomia.dev/bpftime/#roadmap (accessed Jul. 02, 2024).
‌
\[6] “How We Used eBPF to Build Programmable Packet Filtering in Magic Firewall,” The Cloudflare Blog, Dec. 06, 2021. https://blog.cloudflare.com/programmable-packet-filtering-with-magic-firewall (accessed Jul. 05, 2024).
‌
