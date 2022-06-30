#include <bpf/libbpf.h>
#include "capture.skel.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>
#include <time.h>
#include <signal.h>
#include <arpa/inet.h>

#define MAX_CNT 100000ll
#define IF_NAMESIZE     16
#define IFNAMSIZ IF_NAMESIZE
#define XT_TABLE_MAXNAMELEN   32

#define ROUTE_EVT_IF 1
#define ROUTE_EVT_IPTABLE 2

int counter;

int print_libbpf_log(enum libbpf_print_level lvl, const char *fmt, va_list args)
{
    if (lvl >= LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

static __u64 time_get_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static __u64 start_time;
static __u64 cnt;

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
	struct route_evt_t {
		__u64 flags;

		char ifname[IFNAMSIZ];
		__u64 netns;
		__u64 pack_len;
		__u64 ip_version;
		__u8 l4proto;
		__u64 saddr[2];
		__u64 daddr[2];
		__u64 fib_res_addr[2];
		unsigned char fib_res_prefixlen;
		unsigned char fib_res_type;
		__u64 pkt_type;
		__u32 pid;
		__u64 hook;
		__u64 verdict;
		char tablename[XT_TABLE_MAXNAMELEN];
		char processname[16];
	};
	struct route_evt_t* e = (struct route_evt_t*)data;
	// if ((e->flags & ROUTE_EVT_IF) != ROUTE_EVT_IF)
	// 	return;

	// if(e->l4proto==1)
	// 	return;

	struct in_addr sip_addr;
    sip_addr.s_addr = e->saddr[0];

	struct in_addr dip_addr;
    dip_addr.s_addr = e->daddr[0];

	cnt++;
	printf("\n%*llu | %*u | %*s | %*s | %*llu | %*llu | %*s | ", 5,  cnt, -6, e->pid, 16, e->processname, 10, e->ifname, -5, e->pack_len, -5, e->ip_version, -16, inet_ntoa(sip_addr));
	printf("%*s | %*u ", -16, inet_ntoa(dip_addr), -6, e->l4proto);

	if (cnt == MAX_CNT) {
		printf("recv %lld events per sec\n",
		       MAX_CNT * 1000000000ll / (time_get_ns() - start_time));
		return;
	}
}

void trace_reader()
{
	int trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
	if(trace_fd<0) return;

	int count = 0;

	while(1)
	{
		char buffer[1024];
		size_t sz;
		

		sz = read(trace_fd, buffer, sizeof(buffer)-1);
		if(sz>0) 
		{
			count++;
			buffer[sz]=0;
			// printf("%d\t", count);
			puts(buffer);
		}
	}
}

int main(int argc, char **argv)
{
	struct capture_bpf *obj;
	struct perf_buffer *pb;

	int err = 0;
	counter = 0;

	int map_fd, ret = 0;

	char titles[][13] = {"PID", "IF NAME", "FLAGS", "PLEN", "IP_V", "SRC ADDRESS", "DST ADDRESS", "HOOK", "T_NAME", "PROTO", "S_NO", "COMMAND"};

	struct rlimit rlim = {
		.rlim_cur = 512UL << 20,
		.rlim_max = 512UL << 20,
	};

	err = setrlimit(RLIMIT_MEMLOCK, &rlim);
	if (err) {
		fprintf(stderr, "failed to change rlimit\n");
		return 1;
	}

	libbpf_set_print(print_libbpf_log); /* set custom log handler */

	obj = capture_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	err = capture_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object %d\n", err);
		goto cleanup;
	}

    map_fd = bpf_map__fd(obj->maps.route_evt);
    if (map_fd < 0) {
		fprintf(stderr, "ERROR: finding a map in obj file failed\n");
		goto cleanup;
    }

	err = capture_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	pb = perf_buffer__new(map_fd, 8, print_bpf_output, NULL, NULL, NULL);
	ret = libbpf_get_error(pb);
	if (ret) {
		printf("failed to setup perf_buffer: %d\n", ret);
		return 1;
	}

	printf("\n%*s | %*s | %*s | %*s | %*s | %*s | %*s | %*s | %*s", 5, titles[10], -6, titles[0], 16, titles[11], 10, titles[1], -5, titles[3], -5, titles[4], -16, titles[5], -16, titles[6], -6, titles[9]);
/*
 * If the kernel space code is usiing printk statements to debug,
 * Comment out the above print statement and the while statement below.
 * uncomment the trace_reader() function to dsiplay the data that
 * bpf_printk outputs to the trace_pipe file.
 */
	start_time = time_get_ns();
	while ((ret = perf_buffer__poll(pb, 1000)) >= 0 && cnt < MAX_CNT) {
	}
	kill(0, SIGINT);
	// trace_reader();


cleanup:
	capture_bpf__destroy(obj);
	return err != 0;
}
