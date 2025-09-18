#!/bin/bash

# Enhanced service installation script for connection-tracker v2.0
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}╔═══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Connection Tracker v2.0 Service Setup ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (sudo)${NC}"
    exit 1
fi

# System detection
detect_system() {
    echo "Detecting system configuration..."
    
    # Detect OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        OS="unknown"
        VERSION="unknown"
    fi
    
    # Detect systemd
    if ! command -v systemctl &>/dev/null; then
        echo -e "${RED}Error: systemd not found. This installer requires systemd.${NC}"
        exit 1
    fi
    
    # Detect kernel
    KERNEL=$(uname -r)
    KERNEL_MAJOR=$(echo $KERNEL | cut -d. -f1)
    KERNEL_MINOR=$(echo $KERNEL | cut -d. -f2)
    
    echo "  OS: $OS $VERSION"
    echo "  Kernel: $KERNEL"
    echo "  Architecture: $(uname -m)"
    
    # Check kernel compatibility
    if [ "$KERNEL_MAJOR" -lt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 4 ]); then
        echo -e "${YELLOW}⚠ Warning: Kernel may not fully support eBPF${NC}"
        echo "  Recommended: Linux 5.4+"
    fi
}

# Check dependencies
check_dependencies() {
    echo ""
    echo "Checking dependencies..."
    
    local deps_ok=true
    
    # Check for required kernel modules
    if ! lsmod | grep -q "^bpf"; then
        echo -e "${YELLOW}⚠ BPF module not loaded${NC}"
    fi
    
    # Check for BPF filesystem
    if ! mount | grep -q "bpf"; then
        echo -e "${YELLOW}⚠ BPF filesystem not mounted${NC}"
        echo "  Mounting BPF filesystem..."
        mount -t bpf bpf /sys/fs/bpf/ 2>/dev/null || true
    fi
    
    # Check memory limits
    if [ -f /proc/sys/kernel/unprivileged_bpf_disabled ]; then
        BPF_DISABLED=$(cat /proc/sys/kernel/unprivileged_bpf_disabled)
        if [ "$BPF_DISABLED" = "2" ]; then
            echo -e "${YELLOW}⚠ Unprivileged BPF is disabled${NC}"
        fi
    fi
    
    # Check ulimits
    MEMLOCK=$(ulimit -l)
    if [ "$MEMLOCK" != "unlimited" ] && [ "$MEMLOCK" -lt 64000 ]; then
        echo -e "${YELLOW}⚠ Memory lock limit may be too low: $MEMLOCK${NC}"
    fi
    
    echo -e "${GREEN}✓ Dependencies checked${NC}"
}

# Backup existing configuration
backup_existing() {
    if [ -d "/etc/connection-tracker" ]; then
        BACKUP_DIR="/etc/connection-tracker/backup-$(date +%Y%m%d-%H%M%S)"
        echo "Backing up existing configuration to $BACKUP_DIR"
        mkdir -p "$BACKUP_DIR"
        cp -r /etc/connection-tracker/* "$BACKUP_DIR/" 2>/dev/null || true
        echo -e "${GREEN}✓ Backup created${NC}"
    fi
}

# Create directories and install binary
install_binary() {
    echo ""
    echo "Installing connection-tracker..."
    
    # Create directories
    mkdir -p /etc/connection-tracker
    mkdir -p /var/log/connection-tracker
    mkdir -p /var/lib/connection-tracker
    mkdir -p /usr/local/bin
    
    # Find and copy binary
    if [ -f "./connection-tracker" ]; then
        cp ./connection-tracker /usr/local/bin/
    elif [ -f "/tmp/connection-tracker" ]; then
        cp /tmp/connection-tracker /usr/local/bin/
    else
        echo -e "${RED}Error: connection-tracker binary not found!${NC}"
        echo "Please run ./build.sh first"
        exit 1
    fi
    
    chmod +x /usr/local/bin/connection-tracker
    echo -e "${GREEN}✓ Binary installed to /usr/local/bin/connection-tracker${NC}"
}

# Configure backend selection
configure_backends() {
    echo ""
    echo -e "${CYAN}Backend Configuration${NC}"
    echo "═════════════════════"
    echo ""
    echo "Select deployment mode:"
    echo "  1) Elasticsearch only"
    echo "  2) PSM only"  
    echo "  3) Both Elasticsearch and PSM"
    echo "  4) Redis caching only"
    echo "  5) Local only (no external services)"
    echo "  6) Custom (edit config manually)"
    echo ""
    read -p "Enter choice (1-6): " MODE
    
    case $MODE in
        1) create_elastic_config ;;
        2) create_psm_config ;;
        3) create_dual_config ;;
        4) create_redis_config ;;
        5) create_local_config ;;
        6) create_custom_config ;;
        *) create_local_config ;;
    esac
}

create_elastic_config() {
    echo "Creating Elasticsearch configuration..."
    
    read -p "Elasticsearch URL [http://localhost:9200]: " ES_URL
    ES_URL=${ES_URL:-http://localhost:9200}
    
    read -p "Elasticsearch username [elastic]: " ES_USER
    ES_USER=${ES_USER:-elastic}
    
    read -s -p "Elasticsearch password: " ES_PASS
    echo ""
    
    read -p "Index name [connection-events]: " ES_INDEX
    ES_INDEX=${ES_INDEX:-connection-events}
    
    cat > /etc/connection-tracker/config.json << EOF
{
    "hostname": "",
    "hostip": "",
    
    "psm": {
        "enabled": false
    },
    
    "elastic": {
        "enabled": true,
        "urls": ["$ES_URL"],
        "index": "$ES_INDEX",
        "username": "$ES_USER",
        "password": "$ES_PASS",
        "bulk_size": 1000,
        "flush_interval": 5,
        "enable_ssl": $(echo $ES_URL | grep -q "https" && echo "true" || echo "false"),
        "verify_ssl": false
    },
    
    "redis": {
        "enabled": false
    },
    
    "local": {
        "max_events": 10000,
        "log_file": "/var/log/connection-tracker/events.jsonl",
        "log_rotate_size": 100
    },
    
    "debug": false,
    "stats_interval": 60,
    "filter_processes": ["systemd", "kernel"],
    "filter_ports": []
}
EOF
}

create_psm_config() {
    echo "Creating PSM configuration..."
    
    read -p "PSM IP address: " PSM_IP
    read -p "PSM username [admin]: " PSM_USER
    PSM_USER=${PSM_USER:-admin}
    
    read -s -p "PSM password: " PSM_PASS
    echo ""
    
    read -p "Push interval (seconds) [30]: " PUSH_INTERVAL
    PUSH_INTERVAL=${PUSH_INTERVAL:-30}
    
    cat > /etc/connection-tracker/config.json << EOF
{
    "hostname": "",
    "hostip": "",
    
    "psm": {
        "enabled": true,
        "ip_address": "$PSM_IP",
        "username": "$PSM_USER",
        "password": "$PSM_PASS",
        "push_interval": $PUSH_INTERVAL
    },
    
    "elastic": {
        "enabled": false
    },
    
    "redis": {
        "enabled": false
    },
    
    "local": {
        "max_events": 50000,
        "log_file": "/var/log/connection-tracker/events.jsonl"
    },
    
    "debug": false,
    "stats_interval": 60,
    "filter_processes": [],
    "filter_ports": []
}
EOF
}

create_dual_config() {
    echo "Creating dual-backend configuration..."
    
    # Get Elasticsearch settings
    read -p "Elasticsearch URL [http://localhost:9200]: " ES_URL
    ES_URL=${ES_URL:-http://localhost:9200}
    read -p "Elasticsearch username [elastic]: " ES_USER
    ES_USER=${ES_USER:-elastic}
    read -s -p "Elasticsearch password: " ES_PASS
    echo ""
    
    # Get PSM settings
    read -p "PSM IP address: " PSM_IP
    read -p "PSM username [admin]: " PSM_USER
    PSM_USER=${PSM_USER:-admin}
    read -s -p "PSM password: " PSM_PASS
    echo ""
    
    cat > /etc/connection-tracker/config.json << EOF
{
    "hostname": "",
    "hostip": "",
    
    "psm": {
        "enabled": true,
        "ip_address": "$PSM_IP",
        "username": "$PSM_USER",
        "password": "$PSM_PASS",
        "push_interval": 30
    },
    
    "elastic": {
        "enabled": true,
        "urls": ["$ES_URL"],
        "index": "connection-events",
        "username": "$ES_USER",
        "password": "$ES_PASS",
        "bulk_size": 1000,
        "flush_interval": 5
    },
    
    "redis": {
        "enabled": true,
        "address": "localhost:6379",
        "ttl": 3600
    },
    
    "local": {
        "max_events": 50000,
        "log_file": "/var/log/connection-tracker/events.jsonl"
    },
    
    "debug": false,
    "stats_interval": 60
}
EOF
}

create_redis_config() {
    echo "Creating Redis configuration..."
    
    read -p "Redis address [localhost:6379]: " REDIS_ADDR
    REDIS_ADDR=${REDIS_ADDR:-localhost:6379}
    
    cat > /etc/connection-tracker/config.json << EOF
{
    "hostname": "",
    "hostip": "",
    
    "psm": {
        "enabled": false
    },
    
    "elastic": {
        "enabled": false
    },
    
    "redis": {
        "enabled": true,
        "address": "$REDIS_ADDR",
        "password": "",
        "db": 0,
        "ttl": 3600
    },
    
    "local": {
        "max_events": 100000,
        "log_file": "/var/log/connection-tracker/events.jsonl"
    },
    
    "debug": false,
    "stats_interval": 60
}
EOF
}

create_local_config() {
    echo "Creating local-only configuration..."
    
    cat > /etc/connection-tracker/config.json << EOF
{
    "hostname": "",
    "hostip": "",
    
    "psm": {
        "enabled": false
    },
    
    "elastic": {
        "enabled": false
    },
    
    "redis": {
        "enabled": false
    },
    
    "local": {
        "max_events": 100000,
        "log_file": "/var/log/connection-tracker/events.jsonl",
        "log_rotate_size": 100
    },
    
    "debug": true,
    "stats_interval": 30,
    "filter_processes": [],
    "filter_ports": []
}
EOF
}

create_custom_config() {
    echo "Creating template configuration for manual editing..."
    
    cat > /etc/connection-tracker/config.json << EOF
{
    "hostname": "",
    "hostip": "",
    
    "psm": {
        "enabled": false,
        "ip_address": "10.0.0.100",
        "username": "admin",
        "password": "changeme",
        "push_interval": 30
    },
    
    "elastic": {
        "enabled": false,
        "urls": ["http://localhost:9200"],
        "index": "connection-events",
        "username": "elastic",
        "password": "changeme",
        "api_key": "",
        "cloud_id": "",
        "bulk_size": 1000,
        "flush_interval": 5,
        "enable_ssl": false,
        "verify_ssl": false
    },
    
    "redis": {
        "enabled": false,
        "address": "localhost:6379",
        "password": "",
        "db": 0,
        "ttl": 3600
    },
    
    "local": {
        "max_events": 10000,
        "log_file": "/var/log/connection-tracker/events.jsonl",
        "log_rotate_size": 100
    },
    
    "debug": false,
    "stats_interval": 60,
    "filter_processes": ["systemd", "kernel", "sshd"],
    "filter_ports": [22, 53]
}
EOF
}

# Auto-detect and configure host information
configure_host() {
    echo ""
    echo "Auto-detecting host configuration..."
    
    # Detect hostname
    DETECTED_HOSTNAME=$(hostname -f 2>/dev/null || hostname)
    
    # Detect primary IP
    DETECTED_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[^ ]+' || \
                  ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n1)
    
    if [ ! -z "$DETECTED_HOSTNAME" ]; then
        sed -i "s/\"hostname\": \"\"/\"hostname\": \"$DETECTED_HOSTNAME\"/" /etc/connection-tracker/config.json
        echo "  Hostname: $DETECTED_HOSTNAME"
    fi
    
    if [ ! -z "$DETECTED_IP" ]; then
        sed -i "s/\"hostip\": \"\"/\"hostip\": \"$DETECTED_IP\"/" /etc/connection-tracker/config.json
        echo "  IP: $DETECTED_IP"
    fi
    
    echo -e "${GREEN}✓ Host configuration detected${NC}"
}

# Create systemd service
create_service() {
    echo ""
    echo "Creating systemd service..."
    
    cat > /etc/systemd/system/connection-tracker.service << 'EOF'
[Unit]
Description=Connection Tracker v2.0 - eBPF Network Monitor
Documentation=https://github.com/yourorg/connection-tracker
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=root
Group=root
Restart=always
RestartSec=10

# Environment
EnvironmentFile=-/etc/connection-tracker/connection-tracker.env
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Execution
ExecStartPre=/bin/bash -c 'mount | grep -q "^bpf on /sys/fs/bpf" || mount -t bpf bpf /sys/fs/bpf'
ExecStart=/usr/local/bin/connection-tracker --config /etc/connection-tracker/config.json $CT_OPTIONS
ExecReload=/bin/kill -HUP $MAINPID

# Security (still needs root for eBPF)
PrivateTmp=true
ProtectHome=read-only
ProtectSystem=strict
ReadWritePaths=/var/log/connection-tracker /var/lib/connection-tracker /sys/fs/bpf
NoNewPrivileges=false
AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_ADMIN CAP_SYS_RESOURCE CAP_BPF CAP_PERFMON

# Resource limits
LimitNOFILE=1048576
LimitMEMLOCK=infinity
TasksMax=infinity

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=connection-tracker

# Kill settings
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

    # Create environment file
    cat > /etc/connection-tracker/connection-tracker.env << 'EOF'
# Connection Tracker Service Environment
# Uncomment and modify options as needed

# Debug mode (shows all connections)
#DEBUG="--debug"

# Override config file
#CONFIG="--config /etc/connection-tracker/custom.json"

# Override backend enablement
#ENABLE_ELASTIC="--enable-elastic"
#ENABLE_PSM="--enable-psm"
#ENABLE_REDIS="--enable-redis"

# Combined options (used by service)
CT_OPTIONS=""

# Memory limits (in MB)
#GOMEMLIMIT=512MiB
EOF

    echo -e "${GREEN}✓ Systemd service created${NC}"
}

# Create helper scripts
create_helpers() {
    echo ""
    echo "Creating helper scripts..."
    
    # Status script
    cat > /usr/local/bin/ct-status << 'EOF'
#!/bin/bash
echo -e "\033[0;36m═══════════════════════════════════════\033[0m"
echo -e "\033[0;36m     Connection Tracker Status\033[0m"
echo -e "\033[0;36m═══════════════════════════════════════\033[0m"
echo ""
systemctl status connection-tracker --no-pager
echo ""
echo "Active backends:"
grep -E '"enabled": true' /etc/connection-tracker/config.json | head -10
echo ""
echo "Recent events:"
if [ -f /var/log/connection-tracker/events.jsonl ]; then
    tail -5 /var/log/connection-tracker/events.jsonl 2>/dev/null | python3 -m json.tool 2>/dev/null || \
    tail -5 /var/log/connection-tracker/events.jsonl
fi
echo ""
echo "Latest logs:"
journalctl -u connection-tracker -n 20 --no-pager
EOF
    chmod +x /usr/local/bin/ct-status
    
    # Config editor
    cat > /usr/local/bin/ct-config << 'EOF'
#!/bin/bash
${EDITOR:-nano} /etc/connection-tracker/config.json
echo "Config updated. Restart service with: sudo systemctl restart connection-tracker"
EOF
    chmod +x /usr/local/bin/ct-config
    
    # Debug runner
    cat > /usr/local/bin/ct-debug << 'EOF'
#!/bin/bash
echo "Starting Connection Tracker in debug mode..."
echo "Press Ctrl+C to stop"
echo ""
/usr/local/bin/connection-tracker --config /etc/connection-tracker/config.json --debug
EOF
    chmod +x /usr/local/bin/ct-debug
    
    # Test script
    cat > /usr/local/bin/ct-test << 'EOF'
#!/bin/bash
echo "Testing Connection Tracker..."

# Test eBPF loading
echo -n "eBPF programs: "
if bpftool prog list 2>/dev/null | grep -q "kprobe"; then
    echo "✓ Loaded"
else
    echo "✗ Not found"
fi

# Test backends
CONFIG="/etc/connection-tracker/config.json"

# Test Elasticsearch
if grep -q '"elastic".*"enabled": true' $CONFIG; then
    echo -n "Elasticsearch: "
    URL=$(grep -A5 '"elastic"' $CONFIG | grep urls | cut -d'"' -f4)
    if curl -s -o /dev/null -w "%{http_code}" $URL | grep -q "200\|401"; then
        echo "✓ Reachable"
    else
        echo "✗ Unreachable"
    fi
fi

# Test Redis
if grep -q '"redis".*"enabled": true' $CONFIG; then
    echo -n "Redis: "
    ADDR=$(grep -A3 '"redis"' $CONFIG | grep address | cut -d'"' -f4)
    if redis-cli -h ${ADDR%:*} -p ${ADDR#*:} ping 2>/dev/null | grep -q "PONG"; then
        echo "✓ Connected"
    else
        echo "✗ Connection failed"
    fi
fi

# Check service
echo -n "Service: "
if systemctl is-active connection-tracker >/dev/null 2>&1; then
    echo "✓ Running"
else
    echo "✗ Not running"
fi
EOF
    chmod +x /usr/local/bin/ct-test
    
    # Logs viewer
    cat > /usr/local/bin/ct-logs << 'EOF'
#!/bin/bash
journalctl -u connection-tracker -f
EOF
    chmod +x /usr/local/bin/ct-logs
    
    echo -e "${GREEN}✓ Helper scripts created${NC}"
}

# Setup log rotation
setup_logrotate() {
    echo "Setting up log rotation..."
    
    cat > /etc/logrotate.d/connection-tracker << 'EOF'
/var/log/connection-tracker/*.log /var/log/connection-tracker/*.jsonl {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        systemctl reload connection-tracker 2>/dev/null || true
    endscript
}
EOF
    
    echo -e "${GREEN}✓ Log rotation configured${NC}"
}

# Configure firewall if needed
configure_firewall() {
    echo ""
    read -p "Configure firewall rules for backends? (y/n) " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Allow Elasticsearch
        if grep -q '"elastic".*"enabled": true' /etc/connection-tracker/config.json; then
            firewall-cmd --permanent --add-port=9200/tcp 2>/dev/null || \
            ufw allow 9200/tcp 2>/dev/null || \
            iptables -A INPUT -p tcp --dport 9200 -j ACCEPT 2>/dev/null || true
        fi
        
        # Allow Redis
        if grep -q '"redis".*"enabled": true' /etc/connection-tracker/config.json; then
            firewall-cmd --permanent --add-port=6379/tcp 2>/dev/null || \
            ufw allow 6379/tcp 2>/dev/null || \
            iptables -A INPUT -p tcp --dport 6379 -j ACCEPT 2>/dev/null || true
        fi
        
        echo -e "${GREEN}✓ Firewall rules configured${NC}"
    fi
}

# Main installation flow
main() {
    echo ""
    
    # System checks
    detect_system
    check_dependencies
    
    # Backup existing installation
    backup_existing
    
    # Installation
    install_binary
    configure_backends
    configure_host
    create_service
    create_helpers
    setup_logrotate
    
    # Reload systemd
    systemctl daemon-reload
    
    # Optional configurations
    echo ""
    read -p "Edit configuration now? (y/n) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        ${EDITOR:-nano} /etc/connection-tracker/config.json
    fi
    
    configure_firewall
    
    # Summary
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     Installation Complete! ✓          ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${CYAN}📁 Configuration:${NC}"
    echo "   Config:  /etc/connection-tracker/config.json"
    echo "   Logs:    /var/log/connection-tracker/"
    echo "   Data:    /var/lib/connection-tracker/"
    echo ""
    
    echo -e "${CYAN}🔧 Service Management:${NC}"
    echo "   Start:   sudo systemctl start connection-tracker"
    echo "   Stop:    sudo systemctl stop connection-tracker"
    echo "   Status:  sudo systemctl status connection-tracker"
    echo "   Enable:  sudo systemctl enable connection-tracker"
    echo ""
    
    echo -e "${CYAN}🛠️ Helper Commands:${NC}"
    echo "   ct-status  - Show service status"
    echo "   ct-config  - Edit configuration"
    echo "   ct-debug   - Run in debug mode"
    echo "   ct-test    - Test connectivity"
    echo "   ct-logs    - View live logs"
    echo ""
    
    # Start service
    read -p "Start the service now? (y/n) " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Starting service..."
        systemctl start connection-tracker
        sleep 3
        
        if systemctl is-active connection-tracker >/dev/null 2>&1; then
            echo -e "${GREEN}✓ Service started successfully${NC}"
            systemctl status connection-tracker --no-pager
        else
            echo -e "${RED}✗ Service failed to start${NC}"
            echo "Check logs: journalctl -u connection-tracker -n 50"
        fi
        
        echo ""
        read -p "Enable auto-start on boot? (y/n) " -n 1 -r
        echo ""
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            systemctl enable connection-tracker
            echo -e "${GREEN}✓ Service enabled for automatic start${NC}"
        fi
    fi
    
    echo ""
    echo -e "${GREEN}✓ Setup complete!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Verify: ct-test"
    echo "  2. Monitor: ct-logs"
    echo "  3. Configure: ct-config"
}

# Run main function
main "$@"