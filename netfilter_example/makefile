vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

ebpf:
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I . -I ../../libbpf/src/root/usr/include/ -c capture.bpf.c -o capture.bpf.o
	bpftool gen skeleton capture.bpf.o > capture.skel.h

rest:
	clang -g -O2 -Wall -I . -I ../../libbpf/src/root/usr/include/ -c sample_netfilter.c -o sample_netfilter.o
	clang -Wall -O2 -g sample_netfilter.o ../../libbpf/src/build/libbpf.a -lelf -lz -o trace_packets
