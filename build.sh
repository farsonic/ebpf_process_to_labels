#!/bin/bash

set -e

echo "========================================="
echo "Connection Tracker - Build Script"
echo "========================================="

# Create build directory
BUILD_DIR="/tmp/ct-build-$$"
mkdir -p $BUILD_DIR
cd $BUILD_DIR

# Copy source files
cp $OLDPWD/tracker.bpf.c .
cp $OLDPWD/main.go .

# Generate vmlinux.h if needed
if [ ! -f "vmlinux.h" ]; then
    echo "Generating vmlinux.h..."
    if command -v bpftool &>/dev/null; then
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 2>/dev/null || true
    fi

    if [ ! -s "vmlinux.h" ]; then
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

echo "Building eBPF program..."
clang -O2 -g -target bpf -c tracker.bpf.c -o tracker_bpfel.o

echo "Building Go binary..."
go mod init tracker 2>/dev/null || true
go get github.com/cilium/ebpf@latest
CGO_ENABLED=0 go build -ldflags="-s -w" -o connection-tracker main.go

# Copy binary back
cp connection-tracker $OLDPWD/
cd $OLDPWD
rm -rf $BUILD_DIR

echo "✓ Build complete: ./connection-tracker"