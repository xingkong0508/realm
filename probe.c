//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

// 模块一：指挥官 Web 暗号动态白名单 (容量 100)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, __u32);
    __type(value, __u32);
} admin_whitelist SEC(".maps");

// 模块二：商业级百万容量黑名单
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000); 
    __type(key, __u32);           
    __type(value, __u64);         
} blacklist_map SEC(".maps");

// 模块三：击杀遥测
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64); 
} drop_stats_map SEC(".maps");

SEC("xdp")
int realm_xdp_drop(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

    // [新增保命机制]：解析 TCP 层，如果是 22 端口 (SSH)，绝对物理放行，防止指挥官被锁！
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcph + 1) <= data_end) {
            if (tcph->dest == __constant_htons(22) || tcph->source == __constant_htons(22)) {
                return XDP_PASS; // 🛡️ SSH 流量免死金牌
            }
        }
    }

    __u32 src_ip = iph->saddr;

    // 1. 【最高优先级】检查内核级白名单 (Web 端动态下发)
    __u32 *is_admin = bpf_map_lookup_elem(&admin_whitelist, &src_ip);
    if (is_admin) {
        return XDP_PASS; 
    }

    // 2. 【次优先级】检查内核级黑名单
    __u64 *banned_time = bpf_map_lookup_elem(&blacklist_map, &src_ip);
    if (banned_time) {
        __u32 stat_key = 0;
        __u64 *drop_cnt = bpf_map_lookup_elem(&drop_stats_map, &stat_key);
        if (drop_cnt) *drop_cnt += 1;
        return XDP_DROP; // 物理斩首
    }
    
    return XDP_PASS; // 放行至 L2 嗅探器
}

char __license[] SEC("license") = "Dual MIT/GPL";
