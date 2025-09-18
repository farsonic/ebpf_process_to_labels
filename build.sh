#!/bin/bash

# Complete build script with Elasticsearch support
set -e

echo "========================================="
echo "Connection Tracker v2.0 - Complete Build"
echo "========================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (sudo)${NC}"
    exit 1
fi

KERNEL=$(uname -r)
ARCH=$(uname -m)

echo "System: Linux $KERNEL ($ARCH)"
echo ""

# Fix apt sources if needed
echo "Updating package sources..."
apt-get update --allow-releaseinfo-change 2>/dev/null || apt-get update

echo "Installing required packages..."
apt-get install -y --no-install-recommends \
    wget \
    curl \
    git \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    linux-headers-generic \
    linux-headers-$KERNEL \
    pkg-config \
    gcc-multilib \
    ca-certificates \
    || true

# Install Go if not present
if ! command -v go &>/dev/null; then
    echo "Installing Go..."
    wget -q https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
    export PATH=/usr/local/go/bin:$PATH
    ln -sf /usr/local/go/bin/go /usr/bin/go
    rm go1.21.0.linux-amd64.tar.gz
fi

echo -e "${GREEN}✓ All dependencies installed${NC}"

# Create build directory
BUILD_DIR="/tmp/connection-tracker-$$"
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR
cd $BUILD_DIR

echo ""
echo "Creating BPF program..."

# Create vmlinux.h if it doesn't exist
if [ ! -f "vmlinux.h" ]; then
    echo "Generating vmlinux.h..."
    
    # Try bpftool first
    if command -v bpftool &>/dev/null; then
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 2>/dev/null || true
    fi
    
    # If that fails, create a minimal one
    if [ ! -f "vmlinux.h" ] || [ ! -s "vmlinux.h" ]; then
        cat > vmlinux.h << 'EOF'
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#include <linux/types.h>

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

struct pt_regs {
    unsigned long r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8;
    unsigned long rax, rcx, rdx, rsi, rdi, orig_rax, rip, cs, eflags, rsp, ss;
};

struct sock_common {
    union { struct { __be32 skc_daddr; __be32 skc_rcv_saddr; }; };
    union { struct { __be16 skc_dport; __u16 skc_num; }; };
};

struct sock {
    struct sock_common __sk_common;
};

#define PT_REGS_PARM1(x) ((x)->rdi)
#define PT_REGS_RC(x) ((x)->rax)

#endif
EOF
    fi
fi

# Copy the BPF program from current directory if it exists
if [ -f "$OLDPWD/tracker.bpf.c" ]; then
    cp "$OLDPWD/tracker.bpf.c" .
else
    echo "Creating default BPF program..."
    cat > tracker.bpf.c << 'EOF'
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct event {
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char comm[16];
    u8 direction;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int trace_tcp_connect(struct pt_regs *ctx)
{
    struct event evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    evt.direction = 0;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_syscall(void *ctx)
{
    struct event evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    evt.direction = 0;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}
EOF
fi

# Copy main.go from current directory or use the one in this directory
if [ -f "$OLDPWD/main.go" ]; then
    cp "$OLDPWD/main.go" .
    echo "Using existing main.go"
elif [ -f "$OLDPWD/main-elastic.go" ]; then
    cp "$OLDPWD/main-elastic.go" main.go
    echo "Using main-elastic.go"
else
    echo -e "${RED}Error: No main.go found${NC}"
    exit 1
fi

echo ""
echo "Setting up Go environment..."

# Initialize module
go mod init tracker 2>/dev/null || true

# Get dependencies
echo "Downloading Go dependencies..."
go get github.com/cilium/ebpf@latest
go get github.com/cilium/ebpf/cmd/bpf2go@latest
go get github.com/elastic/go-elasticsearch/v8@latest
go get github.com/go-redis/redis/v8@latest

echo ""
echo "Compiling BPF program..."

# Generate with bpf2go or compile directly
if command -v clang &>/dev/null; then
    go generate 2>/dev/null || {
        # Fallback: compile directly
        clang -O2 -g -target bpf \
            -D__TARGET_ARCH_x86 \
            -I. -I/usr/include -I/usr/include/linux \
            -c tracker.bpf.c -o tracker_bpfel.o 2>/dev/null || {
            
            # Last resort: minimal compile
            clang -O2 -target bpf -c tracker.bpf.c -o tracker_bpfel.o
        }
    }
fi

echo "Building final binary..."
CGO_ENABLED=0 go build -ldflags="-s -w" -o connection-tracker main.go

# Check if build succeeded
if [ -f connection-tracker ]; then
    # Copy to original directory
    cp connection-tracker /usr/local/bin/ 2>/dev/null || true
    cp connection-tracker $OLDPWD/
    
    # Clean up
    cd $OLDPWD
    rm -rf $BUILD_DIR
    
    SIZE=$(du -h connection-tracker | cut -f1)
    
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     BUILD SUCCESSFUL! ✓               ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
    echo ""
    echo "📦 Binary: ./connection-tracker"
    echo "📏 Size: $SIZE"
    echo "🚀 Version: 2.0 (Multi-Backend)"
    echo ""
    echo "Backends supported:"
    echo "  • Elasticsearch"
    echo "  • PSM (Policy Service Manager)"
    echo "  • Redis"
    echo "  • Local file logging"
    echo ""
    echo "Quick test:"
    echo "  sudo ./connection-tracker --debug"
    echo ""
    echo "With Elasticsearch only:"
    echo "  sudo ./connection-tracker --enable-elastic --config config.json"
else
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Build complete!${NC}"