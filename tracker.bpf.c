#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

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
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
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

// Kprobe for inbound TCP connections (inet_csk_accept)
SEC("kprobe/inet_csk_accept") 
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

// Tracepoint fallback for connect syscall
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_syscall(struct syscalls_enter_connect_args *ctx) {
    struct conn_event evt = {};
    struct sockaddr_in *addr = (struct sockaddr_in *)ctx->uservaddr;
    
    if (!addr) return 0;
    
    // Check if IPv4
    __u16 family;
    bpf_core_read(&family, sizeof(family), &addr->sin_family);
    if (family != AF_INET) return 0;
    
    // Get process info
    get_task_info(&evt);
    
    // Read destination address
    bpf_core_read(&evt.daddr, sizeof(evt.daddr), &addr->sin_addr.s_addr);
    bpf_core_read(&evt.dport, sizeof(evt.dport), &addr->sin_port);
    
    // Source will be determined by kernel, set to 0 for now
    evt.saddr = 0;
    evt.sport = 0;
    
    evt.direction = 0; // Outbound
    
    // Send event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    
    return 0;
}

// Optional: Track UDP connections via sendto
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_udp_sendto(struct syscalls_enter_sendto_args *ctx) {
    struct conn_event evt = {};
    struct sockaddr_in *addr = (struct sockaddr_in *)ctx->addr;
    
    if (!addr) return 0;
    
    // Check if IPv4
    __u16 family;
    bpf_core_read(&family, sizeof(family), &addr->sin_family);
    if (family != AF_INET) return 0;
    
    // Get process info
    get_task_info(&evt);
    
    // Read destination
    bpf_core_read(&evt.daddr, sizeof(evt.daddr), &addr->sin_addr.s_addr);
    bpf_core_read(&evt.dport, sizeof(evt.dport), &addr->sin_port);
    
    evt.direction = 0; // Outbound UDP
    
    // Basic deduplication for UDP
    __u64 conn_key = ((__u64)evt.pid << 32) | evt.dport;
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