#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔═══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Connection Tracker v2.0 Build Script  ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════╝${NC}"
echo ""

# Check for required tools
check_requirements() {
    local missing=()
    
    echo "Checking build requirements..."
    
    if ! command -v clang &>/dev/null; then
        missing+=("clang")
    fi
    
    if ! command -v go &>/dev/null; then
        missing+=("go")
    fi
    
    if ! command -v bpftool &>/dev/null; then
        echo -e "${YELLOW}Warning: bpftool not found (optional for vmlinux.h generation)${NC}"
    fi
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}Error: Missing required tools: ${missing[*]}${NC}"
        echo ""
        echo "Install requirements:"
        echo "  Ubuntu/Debian: sudo apt install clang llvm golang-go linux-tools-common"
        echo "  RHEL/Fedora:   sudo dnf install clang llvm go kernel-devel"
        echo "  Arch:          sudo pacman -S clang llvm go linux-tools"
        exit 1
    fi
    
    echo -e "${GREEN}✓ All requirements met${NC}"
}

# Check kernel version
check_kernel() {
    echo "Checking kernel compatibility..."
    
    KERNEL_VERSION=$(uname -r)
    KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
    KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)
    
    if [ "$KERNEL_MAJOR" -lt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 4 ]); then
        echo -e "${YELLOW}Warning: Kernel $KERNEL_VERSION may not fully support all eBPF features${NC}"
        echo "  Recommended: Linux 5.4 or later"
        echo "  Some features may be limited"
    else
        echo -e "${GREEN}✓ Kernel $KERNEL_VERSION supported${NC}"
    fi
}

# Generate vmlinux.h if needed
generate_vmlinux() {
    if [ -f "vmlinux.h" ]; then
        echo -e "${GREEN}✓ vmlinux.h exists${NC}"
        return 0
    fi
    
    echo "Generating vmlinux.h..."
    
    # Try bpftool first
    if command -v bpftool &>/dev/null; then
        if bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 2>/dev/null; then
            echo -e "${GREEN}✓ Generated vmlinux.h with bpftool${NC}"
            return 0
        fi
    fi
    
    # Fallback to minimal vmlinux.h
    echo -e "${YELLOW}Creating minimal vmlinux.h fallback${NC}"
    cat > vmlinux.h << 'EOF'
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#include <linux/types.h>

/* Basic types */
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s32 s32;
typedef __s64 s64;

/* x86_64 pt_regs structure */
struct pt_regs {
    unsigned long r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8;
    unsigned long rax, rcx, rdx, rsi, rdi, orig_rax, rip, cs, eflags, rsp, ss;
};

/* Network structures */
struct sock_common {
    union { 
        struct { 
            __be32 skc_daddr; 
            __be32 skc_rcv_saddr; 
        }; 
    };
    union { 
        struct { 
            __be16 skc_dport; 
            __u16 skc_num; 
        }; 
    };
    unsigned short skc_family;
};

struct sock {
    struct sock_common __sk_common;
};

struct task_struct {
    char comm[16];
};

/* BPF helpers */
#define PT_REGS_PARM1(x) ((x)->rdi)
#define PT_REGS_PARM2(x) ((x)->rsi)
#define PT_REGS_PARM3(x) ((x)->rdx)
#define PT_REGS_RC(x) ((x)->rax)

/* Socket constants */
#define AF_INET 2
#define AF_INET6 10

/* Include args for tracepoints */
struct syscalls_enter_connect_args {
    long __syscall_nr;
    long fd;
    void *uservaddr;
    long addrlen;
};

struct syscalls_enter_sendto_args {
    long __syscall_nr;
    long fd;
    void *buff;
    long len;
    long flags;
    void *addr;
    long addr_len;
};

struct sockaddr_in {
    unsigned short sin_family;
    __be16 sin_port;
    struct {
        __be32 s_addr;
    } sin_addr;
};

#endif /* __VMLINUX_H__ */
EOF
}

# Build eBPF program
build_ebpf() {
    echo ""
    echo "Building eBPF program..."
    
    # Check if source exists
    if [ ! -f "tracker.bpf.c" ]; then
        echo -e "${RED}Error: tracker.bpf.c not found!${NC}"
        echo "Make sure tracker.bpf.c is in the current directory"
        exit 1
    fi
    
    # Detect architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            BPF_TARGET="x86"
            ;;
        aarch64)
            BPF_TARGET="arm64"
            ;;
        *)
            BPF_TARGET="x86"
            echo -e "${YELLOW}Warning: Unknown architecture $ARCH, defaulting to x86${NC}"
            ;;
    esac
    
    # Compile eBPF program
    echo "Compiling for $ARCH ($BPF_TARGET)..."
    
    # Include paths for BPF headers
    INCLUDES=""
    for path in /usr/include /usr/include/bpf /usr/local/include/bpf; do
        if [ -d "$path" ]; then
            INCLUDES="$INCLUDES -I$path"
        fi
    done
    
    # Compile with detailed error reporting
    if ! clang -O2 -g -target bpf \
        -D__TARGET_ARCH_${BPF_TARGET} \
        -D__BPF_TRACING__ \
        -Wall -Wno-unused-value -Wno-pointer-sign \
        -Wno-compare-distinct-pointer-types \
        -Werror=implicit-function-declaration \
        -Werror=implicit-int \
        -Werror=incompatible-pointer-types \
        $INCLUDES \
        -c tracker.bpf.c -o tracker_bpfel.o 2>build_errors.log; then
        
        echo -e "${RED}eBPF compilation failed!${NC}"
        echo "Error details:"
        cat build_errors.log
        rm -f build_errors.log
        exit 1
    fi
    
    rm -f build_errors.log
    echo -e "${GREEN}✓ eBPF program compiled successfully${NC}"
    
    # Verify the object file
    if ! file tracker_bpfel.o | grep -q "ELF"; then
        echo -e "${RED}Error: Generated file is not a valid ELF object${NC}"
        exit 1
    fi
    
    # Optional: dump eBPF program info
    if command -v llvm-objdump &>/dev/null; then
        echo ""
        echo "eBPF program sections:"
        llvm-objdump -h tracker_bpfel.o | grep -E "kprobe|tracepoint|xdp|SEC" || true
    fi
}

# Build Go binary
build_go() {
    echo ""
    echo "Building Go binary..."
    
    # Check for main.go
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
    
    # Optional dependencies (may fail)
    go get github.com/elastic/go-elasticsearch/v8@latest 2>/dev/null || \
        echo -e "${YELLOW}Warning: Elasticsearch client not installed${NC}"
    go get github.com/go-redis/redis/v8@latest 2>/dev/null || \
        echo -e "${YELLOW}Warning: Redis client not installed${NC}"
    
    # Build with optimizations
    echo "Compiling Go binary..."
    
    BUILD_FLAGS="-ldflags=-s -w"
    BUILD_FLAGS="$BUILD_FLAGS -ldflags=-X main.Version=2.0.0"
    BUILD_FLAGS="$BUILD_FLAGS -ldflags=-X main.BuildTime=$(date -u +%Y%m%d-%H%M%S)"
    
    if ! CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags="-s -w -X main.Version=2.0.0 -X main.BuildTime=$(date -u +%Y%m%d-%H%M%S)" \
        -o connection-tracker main.go; then
        
        echo -e "${RED}Go compilation failed!${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Go binary compiled successfully${NC}"
    
    # Strip binary for size
    if command -v strip &>/dev/null; then
        echo "Stripping binary..."
        strip connection-tracker 2>/dev/null || true
    fi
}

# Create additional required files if they don't exist
create_supporting_files() {
    # Create backend_clients.go if not exists
    if [ ! -f "backend_clients.go" ]; then
        echo -e "${YELLOW}Creating backend_clients.go placeholder...${NC}"
        echo "// Placeholder - implement backend clients here" > backend_clients.go
    fi
    
    # Create label_enrichment.go if not exists  
    if [ ! -f "label_enrichment.go" ]; then
        echo -e "${YELLOW}Creating label_enrichment.go placeholder...${NC}"
        echo "// Placeholder - implement label enrichment here" > label_enrichment.go
    fi
}

# Test the binary
test_binary() {
    echo ""
    echo "Testing binary..."
    
    # Check if it runs
    if ! sudo ./connection-tracker --version 2>/dev/null; then
        echo -e "${YELLOW}Warning: Binary test failed (may need root privileges)${NC}"
    else
        echo -e "${GREEN}✓ Binary test successful${NC}"
    fi
    
    # Check file size
    SIZE=$(du -h connection-tracker | cut -f1)
    echo "Binary size: $SIZE"
}

# Main build process
main() {
    # Change to script directory
    cd "$(dirname "$0")"
    
    # Run build steps
    check_requirements
    check_kernel
    generate_vmlinux
    create_supporting_files
    build_ebpf
    build_go
    test_binary
    
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║      Build completed successfully!     ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
    echo ""
    echo "Binary: ./connection-tracker"
    echo ""
    echo "Next steps:"
    echo "  1. Test:    sudo ./connection-tracker --debug"
    echo "  2. Install: sudo ./install-service.sh"
    echo "  3. Package: ./package.sh"
    echo ""
    
    # Create a simple test config if none exists
    if [ ! -f "config.json" ]; then
        echo "Creating test configuration..."
        cat > config.json << 'EOF'
{
    "hostname": "",
    "hostip": "",
    "psm": {
        "enabled": false
    },
    "elastic": {
        "enabled": false
    },
    "local": {
        "max_events": 10000,
        "log_file": "/tmp/connection-tracker.log"
    },
    "debug": true,
    "stats_interval": 30
}
EOF
        echo -e "${GREEN}✓ Test config created: config.json${NC}"
    fi
}

# Run main function
main "$@"