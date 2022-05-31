#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define ROUTE_EVT_IF 1
#define ROUTE_EVT_IPTABLE 2
#define ROUTE_EVT_RTTABLE 4 

#define IF_NAMESIZE     16
#define IFNAMSIZ       IF_NAMESIZE
#define XT_TABLE_MAXNAMELEN   32

#define ETH_HLEN    14

struct route_evt_t {
    u64 flags;

    char ifname[IFNAMSIZ];
    u64 netns;

    u64 ip_version; 
    u8 ipproto;
    u64 saddr[2]; 
    u64 daddr[2];
    u64 fib_res_addr[2];
    unsigned char fib_res_prefixlen;
    unsigned char fib_res_type;

    u32 pid;
    u64 hook;
    u64 verdict;
    char tablename[XT_TABLE_MAXNAMELEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} route_evt SEC(".maps");

/*
 * This is to cache ip tables input for now
 */ 
struct ipt_do_table_args
{
    struct sk_buff *skb;
    const struct nf_hook_state *state;
    struct xt_table* table;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct ipt_do_table_args);
} cur_ipt_do_table_args SEC(".maps");

#define MAC_HEADER_SIZE 14;

#define GET_ADDRESS(buffer, member)  (void*) (((char*)buffer) + offsetof(typeof(*buffer), member))
/*
 * Trace SK buffer
 */ 
static inline int do_trace_skb(struct route_evt_t *evt, void *ctx, struct sk_buff *skb)
{
    evt->flags |= ROUTE_EVT_IF;

    // char* head;
    char head[sizeof(skb->head)];
    u16 mac_header;
    u16 network_header;

    bpf_printk("do_trace_skb");

    int err = bpf_skb_load_bytes(skb, offsetof(struct sk_buff, head), head, sizeof(skb->head));

//     bpf_core_read(&head, sizeof(skb->head), GET_ADDRESS(skb, head));
//     bpf_core_read(&mac_header, sizeof(skb->mac_header), GET_ADDRESS(skb, mac_header));
//     bpf_core_read(&network_header, sizeof(skb->network_header), GET_ADDRESS(skb,network_header));

//     if(network_header == 0) {
//         network_header = mac_header + MAC_HEADER_SIZE;
//     }

//     char *ip_header_address = head + network_header;

//     u8 l4proto;

//     bpf_core_read(&evt->ip_version, sizeof(u8), ip_header_address);
//     evt->ip_version = evt->ip_version >> 4 & 0xf;

//     if (evt->ip_version == 4) {
//         struct iphdr iphdr;
//         bpf_core_read(&iphdr, sizeof(iphdr), ip_header_address);

//         l4proto      = iphdr.protocol;
//         evt->saddr[0] = iphdr.saddr;
//         evt->daddr[0] = iphdr.daddr;

//     } else if (evt->ip_version == 6) {
//         struct ipv6hdr* ipv6hdr = (struct ipv6hdr*)ip_header_address;

//         bpf_core_read(&l4proto,  sizeof(ipv6hdr->nexthdr),  (char*)ipv6hdr + offsetof(struct ipv6hdr, nexthdr));
//         bpf_core_read(evt->saddr, sizeof(ipv6hdr->saddr),   (char*)ipv6hdr + offsetof(struct ipv6hdr, saddr));
//         bpf_core_read(evt->daddr, sizeof(ipv6hdr->daddr),   (char*)ipv6hdr + offsetof(struct ipv6hdr, daddr));

//     } else {
//         return -1;
//     }

//     //bpf_printk("IP version : %d",evt->ip_version);
//     //bpf_printk("Protocol : %d",l4proto);

//     struct net_device *dev;
//     bpf_core_read(&dev, sizeof(skb->dev), GET_ADDRESS(skb, dev));

//     bpf_core_read(&evt->ifname, IFNAMSIZ, &dev->name);

//     //bpf_printk("IfName : %s",evt->ifname);

// #ifdef CONFIG_NET_NS
//     struct net* net;

//     possible_net_t *skc_net = &dev->nd_net;
//     bpf_core_read(&net, sizeof(skc_net->net), GET_ADDRESS(skc_net,net));
//     struct ns_common* ns = GET_ADDRESS(net, ns);
//     bpf_core_read(&evt->netns, sizeof(ns->inum), GET_ADDRESS(ns, inum));
// #endif

    return 0;
}

/*
 *  iptables parser
 */

static inline int parse_ip_table_input(struct pt_regs *ctx, struct sk_buff *skb, const struct nf_hook_state *state, struct xt_table *table)
{
    u32 pid = bpf_get_current_pid_tgid();

    struct ipt_do_table_args args = {
        .skb = skb,
        .state = state,
        .table = table,
    };
    bpf_map_update_elem(&cur_ipt_do_table_args, &pid, &args, 0);
    return 0;
};

static inline int parse_ip_table_output(struct pt_regs * ctx)
{
    u32 pid = bpf_get_current_pid_tgid();
    struct ipt_do_table_args *args;
    args = bpf_map_lookup_elem(&cur_ipt_do_table_args, &pid);
    if (args == 0) {
        return 0;
    }
    
    bpf_map_delete_elem(&cur_ipt_do_table_args, &pid);

    struct route_evt_t evt = {
        .flags = ROUTE_EVT_IPTABLE,
        .pid   = pid,
    };

    struct sk_buff *skb = args->skb;
    do_trace_skb(&evt, ctx, skb);

    const struct nf_hook_state *state = args->state;
    bpf_core_read(&evt.hook, sizeof(state->hook), GET_ADDRESS(state, hook));

    struct xt_table* table = args->table;
    bpf_core_read(&evt.tablename, sizeof(table->name), GET_ADDRESS(table, name));

    int ret = PT_REGS_RC(ctx);
    evt.verdict = ret;

    bpf_perf_event_output(ctx, &route_evt, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    return 0;
}

SEC("tp/net/net_dev_queue")
int tracepoint_net_dev_queue(struct trace_event_raw_net_dev_template *ctx)
{
    struct route_evt_t evt = {};
    // void* ctx;
    return do_trace_skb(&evt, ctx, (struct sk_buff *)ctx->skbaddr);
    // bpf_printk("tracepoint_netdevqueue");
    // return 0;
}

// SEC("tp/net/netif_receive_skb")
// int tracepoint_netif_receive_skb(void* ctx, struct sk_buff *skb)
// {
//     struct route_evt_t evt = {};
//     // void* ctx;
//     if(skb==0)
//     {
//         bpf_printk("skb is null");
//         return 0;
//     }
//     return do_trace_skb(&evt, ctx, skb);
//     // bpf_printk("tracepoint_netifrcvskb");
//     // return 0;
// }

SEC("tp/net/netif_receive_skb")
int tracepoint_netif_receive_skb(struct trace_event_raw_net_dev_template *ctx)
{
    struct route_evt_t evt = {};
    // void* ctx;
    return do_trace_skb(&evt, ctx, (struct sk_buff *)ctx->skbaddr);
    // bpf_printk("tracepoint_netdevqueue");
    // return 0;
} 

// SEC("kprobe/net_dev_queue")
// int kprobe__net_dev_queue(struct sk_buff *skb)
// {
//     struct route_evt_t evt = {};
//     void* ctx;
//     return do_trace_skb(&evt, ctx, skb);
// }

// SEC("kprobe/netif_receive_skb")
// int kprobe__netif_receive_skb(struct sk_buff *skb)
// {
//     struct route_evt_t evt = {};
//     void* ctx;
//     return do_trace_skb(&evt, ctx, skb);
// }

/*
 * Kernel probes for iptables
 */

// SEC("kprobe/ipt_do_table")

// int BPF_KPROBE(kprobe__ipt_do_table, struct sk_buff *skb, const struct nf_hook_state *state, struct xt_table *table)
// {
//     bpf_printk("kprobe");
//     return parse_ip_table_input(ctx, skb, state, table);
// };

// SEC("kretprobe/ipt_do_table")

// int BPF_KRETPROBE(kretprobe__ipt_do_table)
// {
//     bpf_printk("kretprobe");
//     return parse_ip_table_output(ctx);
// }

char LICENSE[] SEC("license") = "GPL";
