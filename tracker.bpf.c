#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// Connection event structure
struct conn_event {
    __u32 pid;
    __u32 uid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    char comm[16];
    __u8 direction;
    __u8 action;
    __u64 bytes;
    __u64 timestamp;
} __attribute__((packed));

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Get process info
static __always_inline void get_task_info(struct conn_event *evt) {
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    evt->timestamp = bpf_ktime_get_ns();
}

// TCP connect - outbound connections
SEC("kprobe/tcp_v4_connect")
int trace_tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    struct conn_event evt = {};
    get_task_info(&evt);

    // Read addresses using BPF core read
    bpf_probe_read_kernel(&evt.daddr, sizeof(evt.daddr),
                          &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&evt.saddr, sizeof(evt.saddr),
                          &sk->__sk_common.skc_rcv_saddr);

    // Read ports
    __u16 dport, sport;
    bpf_probe_read_kernel(&dport, sizeof(dport),
                          &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&sport, sizeof(sport),
                          &sk->__sk_common.skc_num);

    evt.dport = bpf_ntohs(dport);
    evt.sport = sport;

    evt.direction = 0; // Outbound
    evt.action = 0;    // Open
    evt.bytes = 0;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

// Accept - inbound connections
SEC("kretprobe/inet_csk_accept")
int trace_tcp_accept(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (!sk) return 0;

    struct conn_event evt = {};
    get_task_info(&evt);

    // For accept, read the accepted socket's addresses
    bpf_probe_read_kernel(&evt.saddr, sizeof(evt.saddr),
                          &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&evt.daddr, sizeof(evt.daddr),
                          &sk->__sk_common.skc_rcv_saddr);

    __u16 sport, dport;
    bpf_probe_read_kernel(&sport, sizeof(sport),
                          &sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&dport, sizeof(dport),
                          &sk->__sk_common.skc_num);

    evt.sport = bpf_ntohs(sport);
    evt.dport = dport;

    evt.direction = 1; // Inbound
    evt.action = 0;    // Open
    evt.bytes = 0;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

// Track data sent
SEC("kprobe/tcp_sendmsg")
int trace_tcp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM3(ctx);

    if (!sk || size == 0) return 0;

    struct conn_event evt = {};
    get_task_info(&evt);

    // Read socket addresses
    bpf_probe_read_kernel(&evt.saddr, sizeof(evt.saddr),
                          &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&evt.daddr, sizeof(evt.daddr),
                          &sk->__sk_common.skc_daddr);

    __u16 sport, dport;
    bpf_probe_read_kernel(&sport, sizeof(sport),
                          &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport),
                          &sk->__sk_common.skc_dport);

    evt.sport = sport;
    evt.dport = bpf_ntohs(dport);

    evt.direction = 0;  // Outbound data
    evt.action = 2;     // Data
    evt.bytes = size;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

// Track connection close
SEC("kprobe/tcp_close")
int trace_tcp_close(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    struct conn_event evt = {};
    get_task_info(&evt);

    // Read addresses before socket is closed
    bpf_probe_read_kernel(&evt.saddr, sizeof(evt.saddr),
                          &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&evt.daddr, sizeof(evt.daddr),
                          &sk->__sk_common.skc_daddr);

    __u16 sport, dport;
    bpf_probe_read_kernel(&sport, sizeof(sport),
                          &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport),
                          &sk->__sk_common.skc_dport);

    evt.sport = sport;
    evt.dport = bpf_ntohs(dport);

    evt.direction = 0;
    evt.action = 1;  // Close
    evt.bytes = 0;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

// Simple UDP send tracking
SEC("kprobe/udp_sendmsg")
int trace_udp_sendmsg(struct pt_regs *ctx) {
    size_t size = (size_t)PT_REGS_PARM3(ctx);
    if (size == 0) return 0;

    struct conn_event evt = {};
    get_task_info(&evt);

    evt.direction = 0;  // Outbound
    evt.action = 2;     // Data
    evt.bytes = size;

    // For UDP, we may not have connection info readily available
    // Just track the data transfer

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}