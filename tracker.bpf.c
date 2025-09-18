#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// Define AF_INET if not in vmlinux.h
#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

// Must match Go Event struct exactly - 37 bytes
struct conn_event {
    __u32 pid;       // 4 bytes
    __u32 uid;       // 4 bytes  
    __u32 saddr;     // 4 bytes
    __u32 daddr;     // 4 bytes
    __u16 sport;     // 2 bytes
    __u16 dport;     // 2 bytes
    char comm[16];   // 16 bytes
    __u8 direction;  // 1 byte
} __attribute__((packed));  // Total: 37 bytes

// Perf event map for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Connection tracking map to avoid duplicates
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);  // PID + port combo
    __type(value, __u64); // Timestamp
    __uint(max_entries, 10240);
} conn_track SEC(".maps");

// Helper to get current task info
static __always_inline void get_task_info(struct conn_event *evt) {
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
}

// Kprobe for outbound TCP connections (tcp_v4_connect)
SEC("kprobe/tcp_v4_connect")
int trace_tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct conn_event evt = {};
    
    // Get process info
    get_task_info(&evt);
    
    // Read socket info
    struct sock_common skc = {};
    bpf_core_read(&skc, sizeof(skc), &sk->__sk_common);
    
    // Extract addresses and ports
    evt.saddr = skc.skc_rcv_saddr;
    evt.daddr = skc.skc_daddr;
    evt.sport = bpf_ntohs(skc.skc_num);
    evt.dport = skc.skc_dport;  // Already in network byte order
    
    evt.direction = 0; // Outbound
    
    // Check if we've seen this connection recently (deduplication)
    __u64 conn_key = ((__u64)evt.pid << 32) | evt.dport;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_seen = bpf_map_lookup_elem(&conn_track, &conn_key);
    
    if (last_seen && (now - *last_seen) < 1000000000) { // 1 second cooldown
        return 0;
    }
    
    // Update tracking map
    bpf_map_update_elem(&conn_track, &conn_key, &now, BPF_ANY);
    
    // Send event to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    
    return 0;
}

// Kretprobe for inbound TCP connections (inet_csk_accept return)
SEC("kretprobe/inet_csk_accept")
int trace_tcp_accept(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    if (!sk) return 0;
    
    struct conn_event evt = {};
    
    // Get process info
    get_task_info(&evt);
    
    // Read socket info
    struct sock_common skc = {};
    bpf_core_read(&skc, sizeof(skc), &sk->__sk_common);
    
    // For accept, source and dest are reversed
    evt.saddr = skc.skc_daddr;
    evt.daddr = skc.skc_rcv_saddr;
    evt.sport = skc.skc_dport;  // Already in network byte order
    evt.dport = bpf_ntohs(skc.skc_num);
    
    evt.direction = 1; // Inbound
    
    // Deduplication
    __u64 conn_key = ((__u64)evt.pid << 32) | evt.sport;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_seen = bpf_map_lookup_elem(&conn_track, &conn_key);
    
    if (last_seen && (now - *last_seen) < 1000000000) {
        return 0;
    }
    
    bpf_map_update_elem(&conn_track, &conn_key, &now, BPF_ANY);
    
    // Send event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    
    return 0;
}

// Alternative: Use raw tracepoint for connect syscall
// This avoids the struct definition issue
SEC("raw_tracepoint/sys_enter")
int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    // Get syscall number
    unsigned long syscall_id = ctx->args[1];
    
    // Check if it's connect syscall (42 on x86_64)
    // You might need to adjust this for your architecture
    #ifdef __x86_64__
    if (syscall_id != 42) // __NR_connect
        return 0;
    #endif
    
    struct conn_event evt = {};
    get_task_info(&evt);
    
    // For raw tracepoint, we have limited access to arguments
    // This is a simplified version
    evt.direction = 0; // Outbound
    
    // Send basic event (without full address details)
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    
    return 0;
}

// Alternative kprobe for socket operations
SEC("kprobe/__sys_connect")
int trace_sys_connect(struct pt_regs *ctx) {
    struct conn_event evt = {};
    
    // Get process info
    get_task_info(&evt);
    
    // Get file descriptor (first argument)
    int fd = (int)PT_REGS_PARM1(ctx);
    
    // For a more complete implementation, you would need to:
    // 1. Look up the file descriptor to get the socket
    // 2. Extract address information from the sockaddr structure
    // For now, we'll just track that a connection was attempted
    
    evt.direction = 0; // Outbound
    
    // Basic deduplication based on PID
    __u64 conn_key = (__u64)evt.pid;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_seen = bpf_map_lookup_elem(&conn_track, &conn_key);
    
    if (last_seen && (now - *last_seen) < 100000000) { // 100ms cooldown
        return 0;
    }
    
    bpf_map_update_elem(&conn_track, &conn_key, &now, BPF_ANY);
    
    // Send event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    
    return 0;
}

// Simplified UDP tracking via kprobe
SEC("kprobe/udp_sendmsg")
int trace_udp_send(struct pt_regs *ctx) {
    struct conn_event evt = {};
    
    // Get process info
    get_task_info(&evt);
    
    evt.direction = 0; // Outbound UDP
    
    // Basic deduplication for UDP
    __u64 conn_key = (__u64)evt.pid;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_seen = bpf_map_lookup_elem(&conn_track, &conn_key);
    
    if (last_seen && (now - *last_seen) < 5000000000) { // 5 second cooldown for UDP
        return 0;
    }
    
    bpf_map_update_elem(&conn_track, &conn_key, &now, BPF_ANY);
    
    // Send event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    
    return 0;
}