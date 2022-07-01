vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

tracer:
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I . -I ../../libbpf/src/root/usr/include/ -c capture.bpf.c -o capture.bpf.o
	bpftool gen skeleton capture.bpf.o > capture.skel.h
	clang -g -O2 -Wall -I . -I ../../libbpf/src/root/usr/include/ -c packet_tracer.c -o packet_tracer.o
	clang -Wall -O2 -g packet_tracer.o ../../libbpf/src/build/libbpf.a -lelf -lz -o trace_packets
	
clean:
	rm -f *.o
	rm trace_packets
	rm *.skel.h
