#!/bin/bash

# Enhanced package script - creates portable bundles for distribution
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

VERSION="2.0.0"
BUILD_DATE=$(date +%Y%m%d-%H%M%S)
ARCH=$(uname -m)
KERNEL=$(uname -r)

echo -e "${BLUE}╔═══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Connection Tracker v2.0 Packager     ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════╝${NC}"
echo ""

# Check for required files
check_files() {
    echo "Checking required files..."
    
    local missing=()
    
    # Check for binary
    if [ ! -f "./connection-tracker" ] && [ ! -f "/usr/local/bin/connection-tracker" ]; then
        missing+=("connection-tracker binary")
    fi
    
    # Check for BPF object
    if [ ! -f "./tracker_bpfel.o" ]; then
        echo -e "${YELLOW}Warning: tracker_bpfel.o not found (may be embedded)${NC}"
    fi
    
    # Check for scripts
    if [ ! -f "./install-service.sh" ]; then
        echo -e "${YELLOW}Warning: install-service.sh not found${NC}"
    fi
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}Error: Missing required files: ${missing[*]}${NC}"
        echo "Please run ./build.sh first"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Required files found${NC}"
}

# Package selection
select_package_type() {
    echo ""
    echo "Select package type:"
    echo ""
    echo "  1) Full package (all backends + source)"
    echo "  2) Elasticsearch package"
    echo "  3) PSM package"
    echo "  4) Minimal package (binary only)"
    echo "  5) Docker container image"
    echo "  6) Kubernetes manifests"
    echo "  7) Development package (with source)"
    echo ""
    read -p "Enter choice (1-7): " PACKAGE_TYPE
    
    case $PACKAGE_TYPE in
        1) create_full_package ;;
        2) create_elastic_package ;;
        3) create_psm_package ;;
        4) create_minimal_package ;;
        5) create_docker_package ;;
        6) create_k8s_package ;;
        7) create_dev_package ;;
        *) create_full_package ;;
    esac
}

# Base package creation
create_base_package() {
    local pkg_suffix=$1
    PACKAGE_NAME="connection-tracker-${VERSION}-${pkg_suffix}-${ARCH}-${BUILD_DATE}"
    
    echo "Creating package: $PACKAGE_NAME"
    mkdir -p "$PACKAGE_NAME"
    
    # Copy binary
    if [ -f "./connection-tracker" ]; then
        cp ./connection-tracker "$PACKAGE_NAME/"
    else
        cp /usr/local/bin/connection-tracker "$PACKAGE_NAME/"
    fi
    
    # Copy scripts
    for script in install-service.sh build.sh package.sh; do
        if [ -f "./$script" ]; then
            cp "./$script" "$PACKAGE_NAME/"
        fi
    done
    
    # Create VERSION file
    cat > "$PACKAGE_NAME/VERSION" << EOF
Version: $VERSION
Package: $pkg_suffix
Built: $(date)
Architecture: $ARCH
Kernel: $KERNEL
Host: $(hostname)
Git Commit: $(git rev-parse HEAD 2>/dev/null || echo "unknown")
EOF
}

# Create full package
create_full_package() {
    create_base_package "full"
    
    # Add all config templates
    mkdir -p "$PACKAGE_NAME/configs"
    
    # Elasticsearch config
    cat > "$PACKAGE_NAME/configs/elastic.json" << 'EOF'
{
    "elastic": {
        "enabled": true,
        "urls": ["http://localhost:9200"],
        "index": "connection-events",
        "username": "elastic",
        "password": "changeme",
        "bulk_size": 1000,
        "flush_interval": 5
    },
    "psm": {"enabled": false},
    "redis": {"enabled": false}
}
EOF
    
    # PSM config
    cat > "$PACKAGE_NAME/configs/psm.json" << 'EOF'
{
    "psm": {
        "enabled": true,
        "ip_address": "10.0.0.100",
        "username": "admin",
        "password": "changeme",
        "push_interval": 30
    },
    "elastic": {"enabled": false},
    "redis": {"enabled": false}
}
EOF
    
    # Dual backend config
    cat > "$PACKAGE_NAME/configs/dual.json" << 'EOF'
{
    "psm": {
        "enabled": true,
        "ip_address": "10.0.0.100",
        "username": "psm-user",
        "password": "psm-pass",
        "push_interval": 30
    },
    "elastic": {
        "enabled": true,
        "urls": ["http://localhost:9200"],
        "index": "connections",
        "username": "elastic",
        "password": "elastic-pass"
    },
    "redis": {
        "enabled": true,
        "address": "localhost:6379",
        "ttl": 3600
    }
}
EOF
    
    # Add documentation
    create_documentation
    
    # Add systemd service file
    create_systemd_files
    
    # Add Docker files
    create_docker_files
    
    # Package it
    finalize_package
}

# Create Elasticsearch-specific package
create_elastic_package() {
    create_base_package "elastic"
    
    # Add Elasticsearch-specific config
    cat > "$PACKAGE_NAME/config.json" << 'EOF'
{
    "hostname": "",
    "hostip": "",
    "elastic": {
        "enabled": true,
        "urls": ["http://localhost:9200"],
        "index": "connection-events",
        "username": "elastic",
        "password": "changeme"
    }
}
EOF
    
    # Add Elasticsearch dashboard
    create_elastic_dashboard
    
    finalize_package
}

# Create PSM-specific package
create_psm_package() {
    create_base_package "psm"
    
    # Add PSM-specific config
    cat > "$PACKAGE_NAME/config.json" << 'EOF'
{
    "hostname": "",
    "hostip": "",
    "psm": {
        "enabled": true,
        "ip_address": "10.0.0.100",
        "username": "admin",
        "password": "changeme",
        "push_interval": 30
    }
}
EOF
    
    # Add PSM integration guide
    cat > "$PACKAGE_NAME/PSM_INTEGRATION.md" << 'EOF'
# PSM Integration Guide

## Configuration
1. Update PSM IP address in config.json
2. Set PSM credentials
3. Adjust push_interval as needed

## Label Mapping
The tracker automatically generates workload labels based on:
- Process name and PID
- Username and UID
- Network connections
- Service detection

## Testing
```bash
sudo ./connection-tracker --debug --config config.json
```

## Verification
Check PSM UI for:
- New workload entries
- Updated labels
- Connection mappings
EOF
    
    finalize_package
}

# Create minimal package
create_minimal_package() {
    PACKAGE_NAME="connection-tracker-${VERSION}-minimal-${ARCH}-${BUILD_DATE}"
    
    echo "Creating minimal package: $PACKAGE_NAME"
    mkdir -p "$PACKAGE_NAME"
    
    # Copy only binary
    if [ -f "./connection-tracker" ]; then
        cp ./connection-tracker "$PACKAGE_NAME/"
    else
        cp /usr/local/bin/connection-tracker "$PACKAGE_NAME/"
    fi
    
    # Simple README
    cat > "$PACKAGE_NAME/README.txt" << EOF
Connection Tracker v${VERSION} - Minimal Package

Usage:
  sudo ./connection-tracker --debug

Create config.json for backend configuration.
EOF
    
    finalize_package
}

# Create Docker package
create_docker_package() {
    create_base_package "docker"
    
    # Create Dockerfile
    cat > "$PACKAGE_NAME/Dockerfile" << 'EOF'
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Copy binary
COPY connection-tracker /usr/local/bin/
RUN chmod +x /usr/local/bin/connection-tracker

# Create directories
RUN mkdir -p /etc/connection-tracker /var/log/connection-tracker

# Copy config
COPY config.json /etc/connection-tracker/

# Run as root (required for eBPF)
USER root

ENTRYPOINT ["/usr/local/bin/connection-tracker"]
CMD ["--config", "/etc/connection-tracker/config.json"]
EOF
    
    # Create docker-compose.yml
    cat > "$PACKAGE_NAME/docker-compose.yml" << 'EOF'
version: '3.8'

services:
  connection-tracker:
    build: .
    image: connection-tracker:v2.0
    container_name: connection-tracker
    privileged: true
    network_mode: host
    pid: host
    volumes:
      - /sys/kernel/debug:/sys/kernel/debug:ro
      - /sys/fs/bpf:/sys/fs/bpf:rw
      - /proc:/proc:ro
      - ./config.json:/etc/connection-tracker/config.json:ro
      - ./logs:/var/log/connection-tracker
    environment:
      - DEBUG=false
    restart: unless-stopped

  # Optional: Elasticsearch
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    container_name: elasticsearch
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
    ports:
      - "9200:9200"
    volumes:
      - es_data:/usr/share/elasticsearch/data

  # Optional: Redis
  redis:
    image: redis:7-alpine
    container_name: redis
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

volumes:
  es_data:
  redis_data:
EOF
    
    # Build script
    cat > "$PACKAGE_NAME/docker-build.sh" << 'EOF'
#!/bin/bash
docker build -t connection-tracker:v2.0 .
echo "Image built: connection-tracker:v2.0"
EOF
    chmod +x "$PACKAGE_NAME/docker-build.sh"
    
    finalize_package
}

# Create Kubernetes package
create_k8s_package() {
    create_base_package "kubernetes"
    
    mkdir -p "$PACKAGE_NAME/kubernetes"
    
    # ConfigMap
    cat > "$PACKAGE_NAME/kubernetes/configmap.yaml" << 'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: connection-tracker-config
  namespace: monitoring
data:
  config.json: |
    {
      "hostname": "",
      "hostip": "",
      "elastic": {
        "enabled": true,
        "urls": ["http://elasticsearch:9200"],
        "index": "k8s-connections"
      },
      "debug": false,
      "stats_interval": 60
    }
EOF
    
    # DaemonSet
    cat > "$PACKAGE_NAME/kubernetes/daemonset.yaml" << 'EOF'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: connection-tracker
  namespace: monitoring
  labels:
    app: connection-tracker
spec:
  selector:
    matchLabels:
      app: connection-tracker
  template:
    metadata:
      labels:
        app: connection-tracker
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: connection-tracker
        image: connection-tracker:v2.0
        imagePullPolicy: IfNotPresent
        securityContext:
          privileged: true
          capabilities:
            add:
            - SYS_ADMIN
            - NET_ADMIN
            - SYS_RESOURCE
            - BPF
            - PERFMON
        volumeMounts:
        - name: config
          mountPath: /etc/connection-tracker
        - name: sys
          mountPath: /sys
        - name: bpf
          mountPath: /sys/fs/bpf
        - name: proc
          mountPath: /proc
          readOnly: true
        - name: logs
          mountPath: /var/log/connection-tracker
        resources:
          limits:
            memory: 512Mi
            cpu: 500m
          requests:
            memory: 256Mi
            cpu: 100m
      volumes:
      - name: config
        configMap:
          name: connection-tracker-config
      - name: sys
        hostPath:
          path: /sys
      - name: bpf
        hostPath:
          path: /sys/fs/bpf
      - name: proc
        hostPath:
          path: /proc
      - name: logs
        emptyDir: {}
      serviceAccount: connection-tracker
      tolerations:
      - effect: NoSchedule
        operator: Exists
      - effect: NoExecute
        operator: Exists
EOF
    
    # ServiceAccount and RBAC
    cat > "$PACKAGE_NAME/kubernetes/rbac.yaml" << 'EOF'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: connection-tracker
  namespace: monitoring
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: connection-tracker
rules:
- apiGroups: [""]
  resources: ["pods", "nodes"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: connection-tracker
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: connection-tracker
subjects:
- kind: ServiceAccount
  name: connection-tracker
  namespace: monitoring
EOF
    
    # Helm chart structure
    create_helm_chart
    
    finalize_package
}

# Create development package
create_dev_package() {
    create_base_package "dev"
    
    # Copy source files
    mkdir -p "$PACKAGE_NAME/src"
    for file in *.go *.c *.h; do
        if [ -f "$file" ]; then
            cp "$file" "$PACKAGE_NAME/src/"
        fi
    done
    
    # Copy go.mod and go.sum
    if [ -f "go.mod" ]; then cp go.mod "$PACKAGE_NAME/"; fi
    if [ -f "go.sum" ]; then cp go.sum "$PACKAGE_NAME/"; fi
    
    # Development README
    cat > "$PACKAGE_NAME/DEVELOPMENT.md" << 'EOF'
# Connection Tracker Development Guide

## Building from Source

### Requirements
- Go 1.21+
- Clang/LLVM 14+
- Linux kernel 5.4+
- bpftool (optional)

### Build Steps
```bash
# Generate vmlinux.h (optional)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Compile eBPF
clang -O2 -g -target bpf -c tracker.bpf.c -o tracker_bpfel.o

# Build Go binary
go build -o connection-tracker main.go
```

## Testing
```bash
# Unit tests
go test ./...

# Integration test
sudo ./test/integration.sh

# Load test
./test/load-test.sh
```

## Debugging
```bash
# Enable debug output
sudo ./connection-tracker --debug

# Check eBPF programs
sudo bpftool prog list

# View maps
sudo bpftool map dump id <map_id>
```
EOF
    
    finalize_package
}

# Create documentation
create_documentation() {
    cat > "$PACKAGE_NAME/README.md" << 'EOF'
# Connection Tracker v2.0

Multi-backend eBPF-based network connection monitoring tool.

## Features
- Real-time connection tracking using eBPF
- Multiple backend support (Elasticsearch, PSM, Redis)
- Process and user attribution
- Container awareness
- Automatic service detection
- Workload labeling for PSM

## Quick Start
```bash
# Extract package
tar xzf connection-tracker-*.tar.gz
cd connection-tracker-*/

# Install
sudo ./install-service.sh

# Or run directly
sudo ./connection-tracker --debug
```

## Backends

### Elasticsearch
- Real-time indexing
- Bulk operations
- SSL/TLS support

### PSM (Policy Service Manager)
- Workload discovery
- Dynamic labeling
- Policy generation

### Redis
- Connection caching
- State management
- TTL support

## System Requirements
- Linux kernel 5.4+
- Root/CAP_BPF privileges
- systemd (for service installation)

## Configuration
Edit `/etc/connection-tracker/config.json` after installation.

## Troubleshooting
- Check logs: `journalctl -u connection-tracker`
- Test mode: `sudo ./connection-tracker --debug`
- Verify BPF: `sudo bpftool prog list`
EOF
}

# Create systemd files
create_systemd_files() {
    mkdir -p "$PACKAGE_NAME/systemd"
    
    # Service file
    cat > "$PACKAGE_NAME/systemd/connection-tracker.service" << 'EOF'
[Unit]
Description=Connection Tracker v2.0
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/connection-tracker --config /etc/connection-tracker/config.json
Restart=always
RestartSec=10
LimitMEMLOCK=infinity
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    
    # Timer for periodic tasks
    cat > "$PACKAGE_NAME/systemd/connection-tracker-cleanup.timer" << 'EOF'
[Unit]
Description=Connection Tracker Cleanup Timer

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF
}

# Create Docker files
create_docker_files() {
    mkdir -p "$PACKAGE_NAME/docker"
    cp "$PACKAGE_NAME/Dockerfile" "$PACKAGE_NAME/docker/" 2>/dev/null || true
}

# Create Elasticsearch dashboard
create_elastic_dashboard() {
    mkdir -p "$PACKAGE_NAME/elasticsearch"
    
    cat > "$PACKAGE_NAME/elasticsearch/dashboard.json" << 'EOF'
{
  "version": "8.11.0",
  "objects": [{
    "id": "connection-tracker-dashboard",
    "type": "dashboard",
    "attributes": {
      "title": "Connection Tracker Dashboard",
      "panels": []
    }
  }]
}
EOF
    
    # Index template
    cat > "$PACKAGE_NAME/elasticsearch/index-template.json" << 'EOF'
{
  "index_patterns": ["connection-events*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    },
    "mappings": {
      "properties": {
        "@timestamp": {"type": "date"},
        "hostname": {"type": "keyword"},
        "process_name": {"type": "keyword"},
        "username": {"type": "keyword"},
        "src_ip": {"type": "ip"},
        "dst_ip": {"type": "ip"},
        "src_port": {"type": "integer"},
        "dst_port": {"type": "integer"}
      }
    }
  }
}
EOF
}

# Create Helm chart
create_helm_chart() {
    mkdir -p "$PACKAGE_NAME/helm/connection-tracker"
    
    # Chart.yaml
    cat > "$PACKAGE_NAME/helm/connection-tracker/Chart.yaml" << EOF
apiVersion: v2
name: connection-tracker
description: eBPF-based connection tracking for Kubernetes
type: application
version: ${VERSION}
appVersion: "${VERSION}"
EOF
    
    # values.yaml
    cat > "$PACKAGE_NAME/helm/connection-tracker/values.yaml" << 'EOF'
image:
  repository: connection-tracker
  tag: v2.0
  pullPolicy: IfNotPresent

config:
  elasticsearch:
    enabled: true
    urls: ["http://elasticsearch:9200"]
  psm:
    enabled: false
  debug: false

resources:
  limits:
    memory: 512Mi
    cpu: 500m
  requests:
    memory: 256Mi
    cpu: 100m
EOF
}

# Finalize package
finalize_package() {
    echo ""
    echo "Creating archive..."
    
    # Create tarball
    tar czf "${PACKAGE_NAME}.tar.gz" "$PACKAGE_NAME/"
    
    # Create checksum
    sha256sum "${PACKAGE_NAME}.tar.gz" > "${PACKAGE_NAME}.tar.gz.sha256"
    
    # Create signature if GPG available
    if command -v gpg &>/dev/null; then
        gpg --armor --detach-sign "${PACKAGE_NAME}.tar.gz" 2>/dev/null || true
    fi
    
    # Cleanup directory
    rm -rf "$PACKAGE_NAME/"
    
    # Calculate size
    SIZE=$(du -h "${PACKAGE_NAME}.tar.gz" | cut -f1)
    
    # Summary
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║      Package Created Successfully!     ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
    echo ""
    echo "📦 Package: ${PACKAGE_NAME}.tar.gz"
    echo "📏 Size: $SIZE"
    echo "🔐 SHA256: ${PACKAGE_NAME}.tar.gz.sha256"
    
    if [ -f "${PACKAGE_NAME}.tar.gz.asc" ]; then
        echo "🔏 Signature: ${PACKAGE_NAME}.tar.gz.asc"
    fi
    
    echo ""
    echo "Distribution:"
    echo "  scp ${PACKAGE_NAME}.tar.gz user@server:/tmp/"
    echo "  ssh user@server"
    echo "  cd /tmp && tar xzf ${PACKAGE_NAME}.tar.gz"
    echo "  cd ${PACKAGE_NAME%.tar.gz}/"
    echo "  sudo ./install-service.sh"
    echo ""
    echo -e "${GREEN}✓ Ready for deployment!${NC}"
}

# Main
main() {
    check_files
    select_package_type
}

main "$@"