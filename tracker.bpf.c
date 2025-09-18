#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#ifndef AF_INET
#define AF_INET 2
#endif

// Connection event with volume tracking
struct conn_event {
    __u32 pid;           // Process ID
    __u32 uid;           // User ID
    __u32 saddr;         // Source IP
    __u32 daddr;         // Destination IP
    __u16 sport;         // Source port
    __u16 dport;         // Destination port
    char comm[16];       // Process name
    __u8 direction;      // 0=outbound, 1=inbound
    __u8 action;         // 0=open, 1=close, 2=data
    __u64 bytes_sent;    // Bytes sent
    __u64 bytes_received;// Bytes received
    __u64 timestamp;     // Event timestamp
} __attribute__((packed));

// Connection state tracking
struct conn_state {
    __u64 start_time;
    __u64 last_seen;
    __u64 bytes_sent;
    __u64 bytes_received;
    __u32 pid;
    __u32 uid;
    char comm[16];
};

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Active connections tracking (5-tuple as key)
struct conn_tuple {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct conn_tuple);
    __type(value, struct conn_state);
    __uint(max_entries, 65536);
} active_connections SEC(".maps");

// Per-socket data tracking
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);  // Socket pointer
    __type(value, struct conn_state);
    __uint(max_entries, 10240);
} socket_tracking SEC(".maps");

// Helper functions
static __always_inline void get_task_info(struct conn_event *evt) {
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    evt->timestamp = bpf_ktime_get_ns();
}

// Track new TCP connection
SEC("kprobe/tcp_v4_connect")
int trace_tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct conn_event evt = {};
    
    get_task_info(&evt);
    
    // Read socket info
    struct sock_common skc = {};
    bpf_core_read(&skc, sizeof(skc), &sk->__sk_common);
    
    evt.saddr = skc.skc_rcv_saddr;
    evt.daddr = skc.skc_daddr;
    evt.sport = bpf_ntohs(skc.skc_num);
    evt.dport = skc.skc_dport;
    evt.direction = 0; // Outbound
    evt.action = 0;    // Open
    
    // Create connection tuple for tracking
    struct conn_tuple tuple = {
        .saddr = evt.saddr,
        .daddr = evt.daddr,
        .sport = evt.sport,
        .dport = bpf_ntohs(evt.dport),
        .protocol = IPPROTO_TCP
    };
    
    // Initialize connection state
    struct conn_state state = {
        .start_time = evt.timestamp,
        .last_seen = evt.timestamp,
        .bytes_sent = 0,
        .bytes_received = 0,
        .pid = evt.pid,
        .uid = evt.uid
    };
    bpf_probe_read_kernel(&state.comm, sizeof(state.comm), evt.comm);
    
    // Store in active connections
    bpf_map_update_elem(&active_connections, &tuple, &state, BPF_ANY);
    
    // Store socket tracking
    __u64 sk_ptr = (__u64)sk;
    bpf_map_update_elem(&socket_tracking, &sk_ptr, &state, BPF_ANY);
    
    // Send event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    
    return 0;
}

// Track accepted connections (inbound)
SEC("kretprobe/inet_csk_accept")
int trace_tcp_accept(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (!sk) return 0;
    
    struct conn_event evt = {};
    get_task_info(&evt);
    
    // Read socket info
    struct sock_common skc = {};
    bpf_core_read(&skc, sizeof(skc), &sk->__sk_common);
    
    evt.saddr = skc.skc_daddr;
    evt.daddr = skc.skc_rcv_saddr;
    evt.sport = skc.skc_dport;
    evt.dport = bpf_ntohs(skc.skc_num);
    evt.direction = 1; // Inbound
    evt.action = 0;    // Open
    
    // Create connection tuple
    struct conn_tuple tuple = {
        .saddr = evt.saddr,
        .daddr = evt.daddr,
        .sport = bpf_ntohs(evt.sport),
        .dport = evt.dport,
        .protocol = IPPROTO_TCP
    };
    
    // Initialize connection state
    struct conn_state state = {
        .start_time = evt.timestamp,
        .last_seen = evt.timestamp,
        .bytes_sent = 0,
        .bytes_received = 0,
        .pid = evt.pid,
        .uid = evt.uid
    };
    bpf_probe_read_kernel(&state.comm, sizeof(state.comm), evt.comm);
    
    bpf_map_update_elem(&active_connections, &tuple, &state, BPF_ANY);
    
    // Store socket tracking
    __u64 sk_ptr = (__u64)sk;
    bpf_map_update_elem(&socket_tracking, &sk_ptr, &state, BPF_ANY);
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    
    return 0;
}

// Track data sent
SEC("kprobe/tcp_sendmsg")
int trace_tcp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM3(ctx);
    
    if (size == 0) return 0;
    
    // Look up socket state
    __u64 sk_ptr = (__u64)sk;
    struct conn_state *state = bpf_map_lookup_elem(&socket_tracking, &sk_ptr);
    if (!state) return 0;
    
    // Update bytes sent
    __sync_fetch_and_add(&state->bytes_sent, size);
    state->last_seen = bpf_ktime_get_ns();
    
    // Send volume update event
    struct conn_event evt = {};
    get_task_info(&evt);
    
    // Read socket info for addresses
    struct sock_common skc = {};
    bpf_core_read(&skc, sizeof(skc), &sk->__sk_common);
    
    evt.saddr = skc.skc_rcv_saddr;
    evt.daddr = skc.skc_daddr;
    evt.sport = bpf_ntohs(skc.skc_num);
    evt.dport = skc.skc_dport;
    evt.direction = 0;  // Outbound data
    evt.action = 2;     // Data transfer
    evt.bytes_sent = size;
    evt.bytes_received = 0;
    
    // Update connection state in active_connections map
    struct conn_tuple tuple = {
        .saddr = evt.saddr,
        .daddr = evt.daddr,
        .sport = evt.sport,
        .dport = bpf_ntohs(evt.dport),
        .protocol = IPPROTO_TCP
    };
    
    struct conn_state *conn = bpf_map_lookup_elem(&active_connections, &tuple);
    if (conn) {
        __sync_fetch_and_add(&conn->bytes_sent, size);
        conn->last_seen = evt.timestamp;
    }
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    
    return 0;
}

// Track data received
SEC("kprobe/tcp_recvmsg")
int trace_tcp_recvmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    
    // We'll track the actual bytes in the return probe
    __u64 sk_ptr = (__u64)sk;
    
    // Store socket pointer for return probe
    bpf_map_update_elem(&socket_tracking, &sk_ptr, &sk_ptr, BPF_ANY);
    
    return 0;
}

SEC("kretprobe/tcp_recvmsg")
int trace_tcp_recvmsg_ret(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;
    
    size_t size = (size_t)ret;
    
    // This is simplified - in production you'd need to track
    // the socket from the kprobe to kretprobe
    
    struct conn_event evt = {};
    get_task_info(&evt);
    evt.direction = 1;  // Inbound data
    evt.action = 2;     // Data transfer
    evt.bytes_sent = 0;
    evt.bytes_received = size;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    
    return 0;
}

// Track connection close
SEC("kprobe/tcp_close")
int trace_tcp_close(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    
    struct conn_event evt = {};
    get_task_info(&evt);
    
    // Read socket info
    struct sock_common skc = {};
    bpf_core_read(&skc, sizeof(skc), &sk->__sk_common);
    
    evt.saddr = skc.skc_rcv_saddr;
    evt.daddr = skc.skc_daddr;
    evt.sport = bpf_ntohs(skc.skc_num);
    evt.dport = skc.skc_dport;
    evt.action = 1;  // Close
    
    // Look up final stats
    struct conn_tuple tuple = {
        .saddr = evt.saddr,
        .daddr = evt.daddr,
        .sport = evt.sport,
        .dport = bpf_ntohs(evt.dport),
        .protocol = IPPROTO_TCP
    };
    
    struct conn_state *state = bpf_map_lookup_elem(&active_connections, &tuple);
    if (state) {
        evt.bytes_sent = state->bytes_sent;
        evt.bytes_received = state->bytes_received;
        
        // Clean up connection from map
        bpf_map_delete_elem(&active_connections, &tuple);
    }
    
    // Clean up socket tracking
    __u64 sk_ptr = (__u64)sk;
    bpf_map_delete_elem(&socket_tracking, &sk_ptr);
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    
    return 0;
}

// Track UDP send
SEC("kprobe/udp_sendmsg")
int trace_udp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    size_t size = (size_t)PT_REGS_PARM3(ctx);
    
    if (size == 0) return 0;
    
    struct conn_event evt = {};
    get_task_info(&evt);
    
    evt.direction = 0;  // Outbound
    evt.action = 2;     // Data transfer  
    evt.bytes_sent = size;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    
    return 0;
}