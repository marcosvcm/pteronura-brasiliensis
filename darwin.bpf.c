#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2
#define TCP_CA_NAME_MAX 16

/* Identifies an active IPv4 connection using a standard 4-tuple key. */
struct conn_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

/* Aggregates socket performance and congestion control metrics. */
struct conn_val {
    char cca[TCP_CA_NAME_MAX];
    __u64 bytes_sent;
    __u32 srtt_us;     /* Smoothed round-trip time (microseconds) */
    __u32 min_rtt_us;  /* Minimum observed round-trip time (microseconds) */
};

/* Map tracking metrics for active IPv4 TCP connections. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct conn_key);
    __type(value, struct conn_val);
} active_conns SEC(".maps");

/* Extracts the IPv4 4-tuple identifiers from the socket structure. */
static __always_inline void get_key(struct sock *sk, struct conn_key *key) {
    key->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
}

/* Captures TCP transmission metrics and updates the active connections map. */
SEC("fentry/tcp_sendmsg")
int BPF_PROG(trace_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    /* Filter out non-IPv4 sockets */
    if (BPF_CORE_READ(sk, __sk_common.skc_family) != AF_INET) return 0;

    struct conn_key key = {};
    get_key(sk, &key);

    struct conn_val val = {};
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;

    val.bytes_sent = BPF_CORE_READ(tp, bytes_sent);
    bpf_probe_read_kernel_str(&val.cca, sizeof(val.cca), 
                                BPF_CORE_READ(icsk, icsk_ca_ops, name));

    /* Convert kernel internal SRTT (scaled by 8) to actual microseconds */
    val.srtt_us = BPF_CORE_READ(tp, srtt_us) >> 3;
    val.min_rtt_us = BPF_CORE_READ(tp, rtt_min[0].rtt);

    bpf_map_update_elem(&active_conns, &key, &val, BPF_ANY);
    return 0;
}

/* Removes tracking entry on socket teardown to prevent map allocation leaks. */
SEC("fentry/tcp_close")
int BPF_PROG(trace_tcp_close, struct sock *sk)
{
    /* Filter out non-IPv4 sockets */
    if (BPF_CORE_READ(sk, __sk_common.skc_family) != AF_INET) return 0;

    struct conn_key key = {};
    get_key(sk, &key);
    bpf_map_delete_elem(&active_conns, &key);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";




