#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

// 退回极度稳定的 Hash Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, __u32);   // Hash 表需要定义 Key
    __type(value, __u32); // 标记是否在黑名单中
} black_list SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16); 
} rb SEC(".maps");

struct event {
    __u32 src_ip;
    __u8  payload[64]; 
};

SEC("xdp")
int xdp_realm_probe(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    __u32 src_ip = ip->saddr;

    // 【法则前置检查】：如果在黑名单结界内，物理级拔管
    __u32 *val = bpf_map_lookup_elem(&black_list, &src_ip);
    if (val) {
        return XDP_DROP; 
    }

    __u8 *payload = (void *)(ip + 1);
    if ((void *)(payload + 64) <= data_end) {
        struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (e) {
            e->src_ip = src_ip;
            bpf_probe_read_kernel(&e->payload, 64, payload);
            bpf_ringbuf_submit(e, 0); 
        }
    }
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
