# eBPF_Project

### Requirements

* The system running this program must have clang to compile the program, I have `clang version 10.0.0-4ubuntu1` for reference.
* The libbpf library must be present on the system. It can be cloned from [here](https://github.com/libbpf/libbpf).
* For the makefile to run properly, the libbpf directory and this directory must be directly under the same parent directory, i.e. the parent directory must have libbpf and eBPF_Project as its direct sub directories.

&nbsp;
### Commands
* To generate the vmlinux.h file: `$ make vmlinux`
    * Note that vmlinux.h is also maintained by libbpf developers, and there might be certain changes from time to time in different versions.

* To generate the object files and executable: `$ make tracer`
The above commmand executes 4 statements:
    * `$ clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I . -I ../../libbpf/src/root/usr/include/ -c capture.bpf.c -o capture.bpf.o`
    To generate the object file from of the kernel space code.
    * `$ bpftool gen skeleton capture.bpf.o > capture.skel.h`
    To generates the skeleton (header file) from the object file. This eases the linkage between the kernel space and user space code.
    * `$ clang -g -O2 -Wall -I . -I ../../libbpf/src/root/usr/include/ -c packet_tracer.c -o packet_tracer.o`
    To generate the object file from the user space code.
    * `$ clang -Wall -O2 -g packet_tracer.o ../../libbpf/src/build/libbpf.a -lelf -lz -o trace_packets`
    To generate the final executable file.

* To run the tracer program: `$ sudo ./trace_packets`

* To clean the directory: `$ make clean`
