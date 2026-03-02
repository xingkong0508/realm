//go:build ignore
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

struct event {
    __u32 src_ip;
    __u8  payload[64];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH); 
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u32);
} black_list SEC(".maps");

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

    __u32 *is_banned = bpf_map_lookup_elem(&black_list, &src_ip);
    if (is_banned && *is_banned == 1) return XDP_DROP;

    int payload_offset = sizeof(*eth) + (ip->ihl * 4);
    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        __u16 *ports = (void *)data + payload_offset;
        if ((void *)(ports + 2) <= data_end) {
            __u16 src_p = __builtin_bswap16(ports[0]);
            __u16 dst_p = __builtin_bswap16(ports[1]);
            if (src_p == 22 || dst_p == 22 || src_p == 443 || dst_p == 443 || src_p == 53 || dst_p == 53) {
                return XDP_PASS;
            }
        }
    }

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return XDP_PASS;
    e->src_ip = src_ip;
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        if (data + payload_offset + i + 1 > data_end) break;
        e->payload[i] = *((__u8 *)(data + payload_offset + i));
    }
    bpf_ringbuf_submit(e, 0);
    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
