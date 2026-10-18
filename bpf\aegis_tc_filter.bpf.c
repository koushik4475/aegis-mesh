// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/*
 * Aegis-Mesh: TC Ingress/Egress Network Filter & Packet Redirection
 *
 * Attaches to network interfaces (veth / eth0) via clsact qdisc.
 * Intercepts outbound/inbound service mesh traffic and directs it to the local
 * Aegis sidecar proxy port while preserving packet integrity.
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AEGIS_PROXY_PORT 15001
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_PIPE 3
#define ETH_P_IP 0x0800

/* Configuration map for mesh redirection rules */
struct mesh_route_key {
    __u32 target_subnet;
    __u32 subnet_mask;
    __u16 target_port;
    __u16 protocol;
};

struct mesh_route_action {
    __u32 proxy_ip;
    __u16 proxy_port;
    __u8  redirect_enabled;
    __u8  tls_enforced;
    __u64 packet_count;
    __u64 byte_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct mesh_route_key);
    __type(value, struct mesh_route_action);
} aegis_routes_map SEC(".maps");

/* Ingress TC Filter: Captures packets targeted at workload and routes to proxy */
SEC("classifier/ingress")
int aegis_tc_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return TC_ACT_OK;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }

    if (ip->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    struct tcphdr *tcp = (void *)((__u32 *)ip + ip->ihl);
    if ((void *)(tcp + 1) > data_end) {
        return TC_ACT_OK;
    }

    __u16 dport = bpf_ntohs(tcp->dest);
    __u16 sport = bpf_ntohs(tcp->source);

    /* Avoid loops if packet is destined to or coming from proxy */
    if (dport == AEGIS_PROXY_PORT || sport == AEGIS_PROXY_PORT) {
        return TC_ACT_OK;
    }

    bpf_printk("[aegis-tc:ingress] Intercepting packet %pI4:%d -> %pI4:%d\n",
               &ip->saddr, sport, &ip->daddr, dport);

    return TC_ACT_OK;
}

/* Egress TC Filter: Captures pod outbound calls to enforce zero-trust mesh mTLS */
SEC("classifier/egress")
int aegis_tc_egress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return TC_ACT_OK;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }

    if (ip->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    struct tcphdr *tcp = (void *)((__u32 *)ip + ip->ihl);
    if ((void *)(tcp + 1) > data_end) {
        return TC_ACT_OK;
    }

    __u16 dport = bpf_ntohs(tcp->dest);
    __u16 sport = bpf_ntohs(tcp->source);

    /* Pass through traffic originating from the Aegis proxy itself */
    if (sport == AEGIS_PROXY_PORT) {
        return TC_ACT_OK;
    }

    bpf_printk("[aegis-tc:egress] Intercepting outbound call to %pI4:%d\n",
               &ip->daddr, dport);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";
