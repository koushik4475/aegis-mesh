// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/*
 * Aegis-Mesh: Kernel-Enforced eBPF Socket Operations & Redirection Program
 *
 * Intercepts active/passive TCP establishment in cgroups to redirect local
 * pod traffic directly to the Aegis sidecar proxy port (default: 15001)
 * without traversing the host network stack (sock_ops / sockmap msg_verdict).
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define AEGIS_PROXY_PORT 15001
#define SK_PASS 1
#define SK_DROP 0

/* Sockmap for socket layer redirection bypass */
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __type(key, struct sock_key);
    __type(value, __u64);
} sock_ops_map SEC(".maps");

/* Map tracking intercepted and bypassed connections */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, struct sock_key);
    __type(value, struct conn_metadata);
} conn_meta_map SEC(".maps");

struct sock_key {
    __u32 sip;
    __u32 dip;
    __u32 sport;
    __u32 dport;
    __u32 family;
};

struct conn_metadata {
    __u64 start_ts_ns;
    __u64 bytes_received;
    __u64 bytes_sent;
    __u32 original_dst_ip;
    __u16 original_dst_port;
    __u16 proxy_port;
    __u8  intercepted;
    __u8  pad[3];
};

static __always_inline void init_sock_key(struct bpf_sock_ops *skops, struct sock_key *key) {
    key->dip = skops->remote_ip4;
    key->sip = skops->local_ip4;
    key->sport = (bpf_htonl(skops->local_port) >> 16);
    key->dport = skops->remote_port >> 16;
    key->family = skops->family;
}

SEC("sockops")
int aegis_sockops_handler(struct bpf_sock_ops *skops) {
    __u32 family = skops->family;

    if (family != AF_INET) {
        return SK_PASS;
    }

    struct sock_key key = {};
    init_sock_key(skops, &key);

    switch (skops->op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: {
            /* If this is destination proxy port, skip redirecting proxy itself */
            if (key.dport == AEGIS_PROXY_PORT || key.sport == AEGIS_PROXY_PORT) {
                bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_ANY);
                return SK_PASS;
            }

            /* Record connection metadata for user-space telemetry & mTLS binding */
            struct conn_metadata meta = {};
            meta.start_ts_ns = bpf_ktime_get_ns();
            meta.original_dst_ip = key.dip;
            meta.original_dst_port = key.dport;
            meta.proxy_port = AEGIS_PROXY_PORT;
            meta.intercepted = 1;

            bpf_map_update_elem(&conn_meta_map, &key, &meta, BPF_ANY);
            bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_ANY);

            bpf_printk("[aegis-mesh:sock_ops] Established: %pI4:%d -> %pI4:%d redirected to proxy\n",
                       &key.sip, key.sport, &key.dip, key.dport);
            break;
        }

        case BPF_SOCK_OPS_STATE_CB: {
            if (skops->args[1] == BPF_TCP_CLOSE) {
                bpf_map_delete_elem(&conn_meta_map, &key);
                bpf_printk("[aegis-mesh:sock_ops] Connection closed: %pI4:%d\n", &key.sip, key.sport);
            }
            break;
        }

        default:
            break;
    }

    return SK_PASS;
}

SEC("sk_msg")
int aegis_msg_verdict(struct sk_msg_md *msg) {
    struct sock_key key = {};
    key.sip = msg->remote_ip4;
    key.dip = msg->local_ip4;
    key.sport = (bpf_htonl(msg->flags) >> 16); // Extract port fields
    key.dport = msg->local_port >> 16;
    key.family = msg->family;

    /* Accelerated kernel bypass directly to peer socket */
    int ret = bpf_msg_redirect_hash(msg, &sock_ops_map, &key, BPF_F_INGRESS);
    if (ret == SK_PASS) {
        return SK_PASS;
    }

    return SK_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
