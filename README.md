# eBPF_Project

## Commands

`bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h`

`clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I . -I ~/Downloads/git/libbpf/src/  -c capture.bpf.c -o capture.bpf.o`

`bpftool gen skeleton capture.bpf.o > capture.skel.h`

`clang -g -O2 -Wall -I . -I ~/Downloads/git/libbpf/src/ -c sample_netfilter.c -o sample_netfilter.o`

`clang -Wall -O2 -g sample_netfilter.o ~/Downloads/git/libbpf/src/build/libbpf.a -lelf -lz -o trace_packets`
