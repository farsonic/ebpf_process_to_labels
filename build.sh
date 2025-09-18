#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔═══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Connection Tracker - Elasticsearch    ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════╝${NC}"
echo ""

# Check for required tools
check_requirements() {
    echo "Checking build requirements..."
    
    local missing=()
    
    if ! command -v clang &>/dev/null; then
        missing+=("clang")
    fi
    
    if ! command -v go &>/dev/null; then
        missing+=("go")
    fi
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}Error: Missing required tools: ${missing[*]}${NC}"
        echo ""
        echo "Install requirements:"
        echo "  Ubuntu/Debian: sudo apt install clang llvm golang-go"
        echo "  RHEL/Fedora:   sudo dnf install clang llvm go"
        exit 1
    fi
    
    echo -e "${GREEN}✓ All requirements met${NC}"
}

# Generate vmlinux.h if needed
generate_vmlinux() {
    if [ -f "vmlinux.h" ]; then
        echo -e "${GREEN}✓ vmlinux.h exists${NC}"
        return 0
    fi
    
    echo "Generating vmlinux.h..."
    
    if command -v bpftool &>/dev/null; then
        if bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 2>/dev/null; then
            echo -e "${GREEN}✓ Generated vmlinux.h with bpftool${NC}"
            return 0
        fi
    fi
    
    # Minimal fallback
    echo -e "${YELLOW}Creating minimal vmlinux.h${NC}"
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
#define PT_REGS_PARM2(x) ((x)->rsi)
#define PT_REGS_PARM3(x) ((x)->rdx)
#define PT_REGS_RC(x) ((x)->rax)

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#endif
EOF
}

# Build eBPF program
build_ebpf() {
    echo ""
    echo "Building eBPF program..."
    
    if [ ! -f "tracker.bpf.c" ]; then
        echo -e "${RED}Error: tracker.bpf.c not found!${NC}"
        exit 1
    fi
    
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) BPF_TARGET="x86" ;;
        aarch64) BPF_TARGET="arm64" ;;
        *) BPF_TARGET="x86" ;;
    esac
    
    echo "Compiling for $ARCH..."
    
    INCLUDES=""
    for path in /usr/include /usr/include/bpf /usr/local/include/bpf; do
        if [ -d "$path" ]; then
            INCLUDES="$INCLUDES -I$path"
        fi
    done
    
    if ! clang -O2 -g -target bpf \
        -D__TARGET_ARCH_${BPF_TARGET} \
        -Wall -Wno-unused-value -Wno-pointer-sign \
        -Wno-compare-distinct-pointer-types \
        $INCLUDES \
        -c tracker.bpf.c -o tracker_bpfel.o 2>build_errors.log; then
        
        echo -e "${RED}eBPF compilation failed!${NC}"
        cat build_errors.log
        rm -f build_errors.log
        exit 1
    fi
    
    rm -f build_errors.log
    echo -e "${GREEN}✓ eBPF program compiled${NC}"
}

# Build Go binary
build_go() {
    echo ""
    echo "Building Go binary..."
    
    if [ ! -f "main.go" ]; then
        echo -e "${RED}Error: main.go not found!${NC}"
        exit 1
    fi
    
    # Initialize go module if needed
    if [ ! -f "go.mod" ]; then
        echo "Initializing Go module..."
        go mod init connection-tracker 2>/dev/null || true
    fi
    
    # Get dependencies
    echo "Fetching dependencies..."
    go get github.com/cilium/ebpf@latest
    go get github.com/cilium/ebpf/link@latest
    go get github.com/cilium/ebpf/perf@latest
    go get github.com/cilium/ebpf/rlimit@latest
    
    # Get Elasticsearch client
    echo "Installing Elasticsearch client..."
    go get github.com/elastic/go-elasticsearch/v8@latest
    go get github.com/elastic/go-elasticsearch/v8/esutil@latest
    
    # Build
    echo "Compiling..."
    if ! CGO_ENABLED=0 go build \
        -ldflags="-s -w -X main.Version=2.0.0" \
        -o connection-tracker main.go; then
        
        echo -e "${RED}Go compilation failed!${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Go binary compiled${NC}"
    
    # Strip for size
    if command -v strip &>/dev/null; then
        strip connection-tracker 2>/dev/null || true
    fi
}

# Create default config
create_config() {
    if [ ! -f "config.json" ]; then
        echo "Creating default configuration..."
        cat > config.json << 'EOF'
{
    "hostname": "",
    "hostip": "",
    "elasticsearch": {
        "urls": ["http://localhost:9200"],
        "index": "connections",
        "username": "",
        "password": "",
        "bulk_size": 500,
        "flush_interval": 5
    },
    "debug": false,
    "stats_interval": 30,
    "track_volume": true
}
EOF
        echo -e "${GREEN}✓ Created config.json${NC}"
    fi
}

# Main build process
main() {
    cd "$(dirname "$0")"
    
    check_requirements
    generate_vmlinux
    build_ebpf
    build_go
    create_config
    
    SIZE=$(du -h connection-tracker | cut -f1)
    
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║      Build completed successfully!     ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
    echo ""
    echo "Binary: ./connection-tracker ($SIZE)"
    echo "Config: ./config.json"
    echo ""
    echo "Quick start:"
    echo "  1. Start Elasticsearch:"
    echo "     docker run -p 9200:9200 -e discovery.type=single-node elasticsearch:8.11.0"
    echo ""
    echo "  2. Edit config.json with your Elasticsearch details"
    echo ""
    echo "  3. Run tracker:"
    echo "     sudo ./connection-tracker --config config.json --debug"
    echo ""
}

main "$@"