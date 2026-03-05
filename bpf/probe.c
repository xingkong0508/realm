//go:build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 核心一：黑名单囚牢 (容量 10万 IP)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, __u32);
} black_list SEC(".maps");

// 核心二：指挥官免死金牌 (白名单，容量 100 IP)
// 只要 IP 在这里面，直接无视所有规则放行
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, __u32);
    __type(value, __u32);
} admin_whitelist SEC(".maps");

SEC("xdp")
int xdp_realm_probe(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // 1. 解析以太网帧
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 只处理 IPv4 流量
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 2. 解析 IP 层
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    // 3. 【最高优先级】检查内核级白名单
    __u32 *is_admin = bpf_map_lookup_elem(&admin_whitelist, &src_ip);
    if (is_admin) {
        return XDP_PASS; // 恭迎指挥官，直接放行
    }

    // 4. 【次优先级】检查内核级黑名单
    __u32 *is_banned = bpf_map_lookup_elem(&black_list, &src_ip);
    if (is_banned) {
        return XDP_DROP; // 物理斩首，丢弃数据包
    }

    // 其他正常流量放行，交给应用层 (Go) 处理
    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";
