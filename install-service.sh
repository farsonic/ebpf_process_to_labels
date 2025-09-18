#!/bin/bash

# Service installation script for connection-tracker v2.0
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

# Check if binary exists
if [ ! -f "./connection-tracker" ] && [ ! -f "/usr/local/bin/connection-tracker" ]; then
    echo -e "${RED}Error: connection-tracker binary not found!${NC}"
    echo "Please run ./build.sh first"
    exit 1
fi

# Create directories
echo "Creating directories..."
mkdir -p /etc/connection-tracker
mkdir -p /var/log/connection-tracker
mkdir -p /var/lib/connection-tracker

# Copy binary if needed
if [ -f "./connection-tracker" ]; then
    echo "Installing binary..."
    cp ./connection-tracker /usr/local/bin/
    chmod +x /usr/local/bin/connection-tracker
    echo -e "${GREEN}✓ Binary installed to /usr/local/bin/connection-tracker${NC}"
fi

# Deployment mode selection
echo ""
echo "Select deployment mode:"
echo "  1) Elasticsearch only (no PSM)"
echo "  2) PSM only (no Elasticsearch)"
echo "  3) Both Elasticsearch and PSM"
echo "  4) Local only (no external services)"
echo "  5) Custom (edit config manually)"
echo ""
read -p "Enter choice (1-5): " MODE

# Create appropriate config based on selection
case $MODE in
    1)
        echo "Creating Elasticsearch-only configuration..."
        cat > /etc/connection-tracker/config.json << 'EOF'
{
    "hostname": "",
    "hostip": "",
    
    "psm": {
        "enabled": false
    },
    
    "elastic": {
        "enabled": true,
        "urls": ["http://localhost:9200"],
        "index": "connection-events",
        "username": "elastic",
        "password": "changeme",
        "bulk_size": 1000,
        "flush_interval": 5
    },
    
    "redis": {
        "enabled": false
    },
    
    "local": {
        "max_events": 10000,
        "log_file": "/var/log/connection-tracker/events.jsonl"
    },
    
    "debug": false,
    "stats_interval": 60
}
EOF
        ;;
        
    2)
        echo "Creating PSM-only configuration..."
        cat > /etc/connection-tracker/config.json << 'EOF'
{
    "hostname": "",
    "hostip": "",
    
    "psm": {
        "enabled": true,
        "ip_address": "10.0.0.100",
        "username": "admin",
        "password": "changeme",
        "push_interval": 30
    },
    
    "elastic": {
        "enabled": false
    },
    
    "redis": {
        "enabled": false
    },
    
    "local": {
        "max_events": 10000
    },
    
    "debug": false,
    "stats_interval": 60
}
EOF
        ;;
        
    3)
        echo "Creating dual-backend configuration..."
        cat > /etc/connection-tracker/config.json << 'EOF'
{
    "hostname": "",
    "hostip": "",
    
    "psm": {
        "enabled": true,
        "ip_address": "10.0.0.100",
        "username": "admin",
        "password": "psm-password",
        "push_interval": 30
    },
    
    "elastic": {
        "enabled": true,
        "urls": ["http://localhost:9200"],
        "index": "connection-events",
        "username": "elastic",
        "password": "elastic-password",
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
        ;;
        
    4)
        echo "Creating local-only configuration..."
        cat > /etc/connection-tracker/config.json << 'EOF'
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
    "stats_interval": 30
}
EOF
        ;;
        
    5)
        echo "Creating default configuration for manual editing..."
        cat > /etc/connection-tracker/config.json << 'EOF'
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
        "bulk_size": 1000,
        "flush_interval": 5
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
        "log_file": "/var/log/connection-tracker/events.jsonl"
    },
    
    "debug": false,
    "stats_interval": 60
}
EOF
        ;;
esac

# Auto-detect hostname and IP
DETECTED_HOSTNAME=$(hostname)
DETECTED_IP=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n1)

if [ ! -z "$DETECTED_HOSTNAME" ]; then
    sed -i "s/\"hostname\": \"\"/\"hostname\": \"$DETECTED_HOSTNAME\"/" /etc/connection-tracker/config.json
fi

if [ ! -z "$DETECTED_IP" ]; then
    sed -i "s/\"hostip\": \"\"/\"hostip\": \"$DETECTED_IP\"/" /etc/connection-tracker/config.json
fi

echo -e "${GREEN}✓ Config created at /etc/connection-tracker/config.json${NC}"
echo "  Detected hostname: $DETECTED_HOSTNAME"
echo "  Detected IP: $DETECTED_IP"

# Create environment file
cat > /etc/connection-tracker/connection-tracker.env << 'EOF'
# Connection Tracker Service Environment
# Uncomment and modify options as needed

# Debug mode (shows all connections)
#DEBUG="--debug"

# Override backend enablement
#ENABLE_ELASTIC="--enable-elastic"
#ENABLE_PSM="--enable-psm"
#ENABLE_REDIS="--enable-redis"

# Combined options (used by systemd service)
CT_OPTIONS=""
EOF

echo -e "${GREEN}✓ Environment file created${NC}"

# Create systemd service file
echo "Creating systemd service..."

cat > /etc/systemd/system/connection-tracker.service << 'EOF'
[Unit]
Description=Connection Tracker v2.0 - Multi-Backend eBPF Monitor
Documentation=https://github.com/yourorg/connection-tracker
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root

# Environment file for options
EnvironmentFile=-/etc/connection-tracker/connection-tracker.env

# Main service command
ExecStart=/usr/local/bin/connection-tracker --config /etc/connection-tracker/config.json $CT_OPTIONS

# Restart policy
Restart=on-failure
RestartSec=10
StartLimitInterval=60
StartLimitBurst=3

# Security settings (still needs root for eBPF)
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/log/connection-tracker /var/lib/connection-tracker
NoNewPrivileges=false

# Resource limits
LimitNOFILE=65536
LimitMEMLOCK=infinity

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=connection-tracker

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}✓ Systemd service created${NC}"

# Create log rotation
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

# Create helper scripts
echo "Creating helper scripts..."

cat > /usr/local/bin/ct-status << 'EOF'
#!/bin/bash
echo "Connection Tracker Status"
echo "========================="
systemctl status connection-tracker --no-pager
echo ""
echo "Active backends:"
grep -E "enabled|urls|ip_address" /etc/connection-tracker/config.json | head -20
echo ""
echo "Recent logs:"
journalctl -u connection-tracker -n 20 --no-pager
EOF
chmod +x /usr/local/bin/ct-status

cat > /usr/local/bin/ct-config << 'EOF'
#!/bin/bash
${EDITOR:-nano} /etc/connection-tracker/config.json
echo "Config updated. Restart service with: sudo systemctl restart connection-tracker"
EOF
chmod +x /usr/local/bin/ct-config

cat > /usr/local/bin/ct-debug << 'EOF'
#!/bin/bash
echo "Starting Connection Tracker in debug mode..."
/usr/local/bin/connection-tracker --config /etc/connection-tracker/config.json --debug
EOF
chmod +x /usr/local/bin/ct-debug

cat > /usr/local/bin/ct-test-elastic << 'EOF'
#!/bin/bash
echo "Testing Elasticsearch connection..."
CONFIG="/etc/connection-tracker/config.json"
URL=$(grep -A5 '"elastic"' $CONFIG | grep urls | cut -d'"' -f4)
USER=$(grep -A5 '"elastic"' $CONFIG | grep username | cut -d'"' -f4)
PASS=$(grep -A5 '"elastic"' $CONFIG | grep password | cut -d'"' -f4)

if [ ! -z "$URL" ]; then
    echo "Testing $URL..."
    if [ ! -z "$USER" ]; then
        curl -u "$USER:$PASS" "$URL" 2>/dev/null | python3 -m json.tool | head -20
    else
        curl "$URL" 2>/dev/null | python3 -m json.tool | head -20
    fi
else
    echo "Elasticsearch not configured"
fi
EOF
chmod +x /usr/local/bin/ct-test-elastic

# Reload systemd
systemctl daemon-reload

echo -e "${GREEN}✓ Helper scripts created${NC}"

# Ask about editing config
if [ "$MODE" != "4" ]; then
    echo ""
    read -p "Edit configuration now? (y/n) " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        ${EDITOR:-nano} /etc/connection-tracker/config.json
    fi
fi

# Summary
echo ""
echo -e "${BLUE}╔═══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     Installation Complete! ✓          ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════╝${NC}"
echo ""

case $MODE in
    1) echo "Mode: Elasticsearch-only" ;;
    2) echo "Mode: PSM-only" ;;
    3) echo "Mode: Dual-backend (Elastic + PSM)" ;;
    4) echo "Mode: Local-only" ;;
    5) echo "Mode: Custom" ;;
esac

echo ""
echo -e "${GREEN}📁 Configuration:${NC}"
echo "   Config: /etc/connection-tracker/config.json"
echo "   Logs:   /var/log/connection-tracker/"
echo ""
echo -e "${GREEN}🔧 Service Management:${NC}"
echo "   Start:   sudo systemctl start connection-tracker"
echo "   Stop:    sudo systemctl stop connection-tracker"
echo "   Restart: sudo systemctl restart connection-tracker"
echo "   Status:  sudo systemctl status connection-tracker"
echo "   Enable:  sudo systemctl enable connection-tracker"
echo ""
echo -e "${GREEN}🛠️ Helper Commands:${NC}"
echo "   ct-status       - Show service status"
echo "   ct-config       - Edit configuration"
echo "   ct-debug        - Run in debug mode"
echo "   ct-test-elastic - Test Elasticsearch connection"
echo ""

# Start service prompt
read -p "Start the service now? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    systemctl start connection-tracker
    sleep 2
    systemctl status connection-tracker --no-pager
    
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