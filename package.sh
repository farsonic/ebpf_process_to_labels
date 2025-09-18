#!/bin/bash

# Package script - creates portable bundles for distribution
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

VERSION="2.0.0"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ARCH=$(uname -m)

echo -e "${BLUE}╔═══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Connection Tracker v2.0 Bundle Creator║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════╝${NC}"
echo ""

# Package type selection
echo "Select package type:"
echo "  1) Full package (all backends)"
echo "  2) Elasticsearch-only package"
echo "  3) PSM-only package"
echo "  4) Minimal package (local only)"
echo ""
read -p "Enter choice (1-4): " PACKAGE_TYPE

case $PACKAGE_TYPE in
    1) PACKAGE_SUFFIX="full" ;;
    2) PACKAGE_SUFFIX="elastic" ;;
    3) PACKAGE_SUFFIX="psm" ;;
    4) PACKAGE_SUFFIX="minimal" ;;
    *) PACKAGE_SUFFIX="full" ;;
esac

PACKAGE_NAME="connection-tracker-${VERSION}-${PACKAGE_SUFFIX}-${ARCH}-${TIMESTAMP}"

# Check if binary exists
if [ ! -f "./connection-tracker" ] && [ ! -f "/usr/local/bin/connection-tracker" ]; then
    echo -e "${RED}Error: connection-tracker binary not found!${NC}"
    echo "Please run ./build.sh first"
    exit 1
fi

# Create package directory
echo "Creating package structure..."
mkdir -p "$PACKAGE_NAME"

# Copy binary
if [ -f "./connection-tracker" ]; then
    cp ./connection-tracker "$PACKAGE_NAME/"
elif [ -f "/usr/local/bin/connection-tracker" ]; then
    cp /usr/local/bin/connection-tracker "$PACKAGE_NAME/"
fi

echo -e "${GREEN}✓ Binary included${NC}"

# Create the installer script
cat > "$PACKAGE_NAME/install.sh" << 'INSTALLER_SCRIPT'
#!/bin/bash

# All-in-one installer for Connection Tracker v2.0
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔═══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Connection Tracker v2.0 Quick Install ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (sudo)${NC}"
    exit 1
fi

# Detect system
KERNEL=$(uname -r)
ARCH=$(uname -m)
OS="unknown"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
fi

echo "System Detection:"
echo "  OS: $OS"
echo "  Kernel: $KERNEL"
echo "  Arch: $ARCH"
echo ""

# Check kernel version
KERNEL_MAJOR=$(echo $KERNEL | cut -d. -f1)
KERNEL_MINOR=$(echo $KERNEL | cut -d. -f2)

if [ "$KERNEL_MAJOR" -lt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 4 ]); then
    echo -e "${YELLOW}Warning: Kernel version $KERNEL_MAJOR.$KERNEL_MINOR may not fully support eBPF${NC}"
    echo "Recommended: Linux 5.4+"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Installation options
echo "Installation Options:"
echo "  1) Full installation (service + config)"
echo "  2) Binary only (manual mode)"
echo "  3) Upgrade existing installation"
echo ""
read -p "Select option (1-3): " -n 1 INSTALL_MODE
echo ""
echo ""

# Create directories
mkdir -p /etc/connection-tracker
mkdir -p /var/log/connection-tracker
mkdir -p /var/lib/connection-tracker

# Install binary
echo "Installing binary..."
cp ./connection-tracker /usr/local/bin/
chmod +x /usr/local/bin/connection-tracker
echo -e "${GREEN}✓ Binary installed to /usr/local/bin/${NC}"

if [ "$INSTALL_MODE" == "2" ]; then
    echo ""
    echo -e "${GREEN}Binary-only installation complete!${NC}"
    echo ""
    echo "Run with:"
    echo "  sudo connection-tracker --debug"
    echo ""
    echo "Or with config:"
    echo "  sudo connection-tracker --config /path/to/config.json"
    exit 0
fi

if [ "$INSTALL_MODE" == "3" ]; then
    echo ""
    echo "Restarting service with new binary..."
    systemctl restart connection-tracker 2>/dev/null || true
    echo -e "${GREEN}✓ Upgrade complete!${NC}"
    systemctl status connection-tracker --no-pager 2>/dev/null || true
    exit 0
fi

# Full installation - copy appropriate config
if [ -f "./config-elastic.json" ]; then
    cp ./config-elastic.json /etc/connection-tracker/config.json
elif [ -f "./config-psm.json" ]; then
    cp ./config-psm.json /etc/connection-tracker/config.json
elif [ -f "./config.json" ]; then
    cp ./config.json /etc/connection-tracker/config.json
else
    # Create default config
    cat > /etc/connection-tracker/config.json << 'EOF'
{
    "hostname": "",
    "hostip": "",
    
    "psm": {
        "enabled": false
    },
    
    "elastic": {
        "enabled": false,
        "urls": ["http://localhost:9200"],
        "index": "connection-events"
    },
    
    "local": {
        "max_events": 10000,
        "log_file": "/var/log/connection-tracker/events.jsonl"
    },
    
    "debug": false,
    "stats_interval": 60
}
EOF
fi

# Auto-detect hostname and IP
DETECTED_HOSTNAME=$(hostname)
DETECTED_IP=$(ip -4 addr show 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n1)

if [ ! -z "$DETECTED_HOSTNAME" ]; then
    sed -i "s/\"hostname\": \"\"/\"hostname\": \"$DETECTED_HOSTNAME\"/" /etc/connection-tracker/config.json
fi

if [ ! -z "$DETECTED_IP" ]; then
    sed -i "s/\"hostip\": \"\"/\"hostip\": \"$DETECTED_IP\"/" /etc/connection-tracker/config.json
fi

echo -e "${GREEN}✓ Config created${NC}"

# Install systemd service
cat > /etc/systemd/system/connection-tracker.service << 'EOF'
[Unit]
Description=Connection Tracker v2.0
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/connection-tracker --config /etc/connection-tracker/config.json
Restart=on-failure
RestartSec=10
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF

# Create helper scripts
cat > /usr/local/bin/ct-status << 'EOF'
#!/bin/bash
systemctl status connection-tracker --no-pager
journalctl -u connection-tracker -n 20 --no-pager
EOF
chmod +x /usr/local/bin/ct-status

# Reload systemd
systemctl daemon-reload

echo -e "${GREEN}✓ Service installed${NC}"

# Quick config
echo ""
echo "Current configuration:"
grep -E "enabled" /etc/connection-tracker/config.json | head -10
echo ""
read -p "Edit config now? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    ${EDITOR:-nano} /etc/connection-tracker/config.json
fi

# Start service
echo ""
read -p "Start the service now? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    systemctl start connection-tracker
    sleep 2
    systemctl status connection-tracker --no-pager
fi

echo ""
echo -e "${GREEN}✓ Installation complete!${NC}"
echo ""
echo "Commands:"
echo "  sudo systemctl [start|stop|restart|status] connection-tracker"
echo "  sudo journalctl -u connection-tracker -f"
echo "  ct-status"
INSTALLER_SCRIPT

chmod +x "$PACKAGE_NAME/install.sh"

# Create uninstaller
cat > "$PACKAGE_NAME/uninstall.sh" << 'UNINSTALLER_SCRIPT'
#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

echo "Connection Tracker Uninstaller"
echo "=============================="

if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (sudo)${NC}"
    exit 1
fi

systemctl stop connection-tracker 2>/dev/null || true
systemctl disable connection-tracker 2>/dev/null || true

rm -f /etc/systemd/system/connection-tracker.service
rm -rf /etc/connection-tracker
rm -rf /var/log/connection-tracker
rm -rf /var/lib/connection-tracker
rm -f /usr/local/bin/connection-tracker
rm -f /usr/local/bin/ct-*

systemctl daemon-reload

echo -e "${GREEN}✓ Uninstall complete${NC}"
UNINSTALLER_SCRIPT

chmod +x "$PACKAGE_NAME/uninstall.sh"

# Create README
cat > "$PACKAGE_NAME/README.md" << 'README_CONTENT'
# Connection Tracker v2.0 - Multi-Backend

## Quick Start

```bash
# Extract and install
tar xzf connection-tracker-*.tar.gz
cd connection-tracker-*/
sudo ./install.sh
```

## Backend Configuration

### Elasticsearch Only
Edit `/etc/connection-tracker/config.json`:
```json
{
    "elastic": {
        "enabled": true,
        "urls": ["http://localhost:9200"],
        "index": "connections"
    },
    "psm": {
        "enabled": false
    }
}
```

### PSM Only
```json
{
    "psm": {
        "enabled": true,
        "ip_address": "10.0.0.100",
        "username": "admin",
        "password": "password"
    },
    "elastic": {
        "enabled": false
    }
}
```

### Both Backends
Enable both `elastic` and `psm` sections.

## Commands

- `sudo systemctl start connection-tracker`
- `sudo systemctl status connection-tracker`
- `sudo journalctl -u connection-tracker -f`
- `ct-status` - Quick status check

## Requirements

- Linux kernel 5.4+
- Root privileges
- Optional: Elasticsearch 7.x/8.x
- Optional: PSM server
- Optional: Redis

## Troubleshooting

Check logs: `sudo journalctl -u connection-tracker -n 100`

Test mode: `sudo connection-tracker --debug`
README_CONTENT

# Add appropriate sample configs based on package type
case $PACKAGE_TYPE in
    2)  # Elasticsearch-only
        cat > "$PACKAGE_NAME/config-elastic.json" << 'EOF'
{
    "hostname": "",
    "hostip": "",
    "elastic": {
        "enabled": true,
        "urls": ["http://localhost:9200"],
        "index": "connection-events",
        "username": "elastic",
        "password": "changeme"
    },
    "psm": {"enabled": false}
}
EOF
        ;;
    3)  # PSM-only
        cat > "$PACKAGE_NAME/config-psm.json" << 'EOF'
{
    "hostname": "",
    "hostip": "",
    "psm": {
        "enabled": true,
        "ip_address": "10.0.0.100",
        "username": "admin",
        "password": "changeme"
    },
    "elastic": {"enabled": false}
}
EOF
        ;;
    *)  # Full or minimal - include both sample configs
        cat > "$PACKAGE_NAME/config-elastic.json" << 'EOF'
{
    "elastic": {"enabled": true, "urls": ["http://localhost:9200"]},
    "psm": {"enabled": false}
}
EOF
        cat > "$PACKAGE_NAME/config-psm.json" << 'EOF'
{
    "psm": {"enabled": true, "ip_address": "10.0.0.100"},
    "elastic": {"enabled": false}
}
EOF
        ;;
esac

# Create VERSION file
cat > "$PACKAGE_NAME/VERSION" << EOF
Version: $VERSION
Package: $PACKAGE_SUFFIX
Built: $(date)
Arch: $ARCH
Host: $(hostname)
EOF

# Create the tarball
echo ""
echo "Creating tarball..."
tar czf "${PACKAGE_NAME}.tar.gz" "$PACKAGE_NAME/"

# Calculate checksum
sha256sum "${PACKAGE_NAME}.tar.gz" > "${PACKAGE_NAME}.tar.gz.sha256"

# Clean up directory
rm -rf "$PACKAGE_NAME/"

# Final size
SIZE=$(du -h "${PACKAGE_NAME}.tar.gz" | cut -f1)

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║      Bundle Created Successfully!     ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
echo ""
echo "📦 Package: ${PACKAGE_NAME}.tar.gz"
echo "📏 Size: $SIZE"
echo "🔐 Checksum: ${PACKAGE_NAME}.tar.gz.sha256"
echo ""

case $PACKAGE_TYPE in
    1) echo "Type: Full (all backends)" ;;
    2) echo "Type: Elasticsearch-only" ;;
    3) echo "Type: PSM-only" ;;
    4) echo "Type: Minimal (local only)" ;;
esac

echo ""
echo "Deployment:"
echo "  scp ${PACKAGE_NAME}.tar.gz user@target:/tmp/"
echo "  ssh user@target"
echo "  cd /tmp && tar xzf ${PACKAGE_NAME}.tar.gz"
echo "  cd ${PACKAGE_NAME%.tar.gz}/"
echo "  sudo ./install.sh"
echo ""
echo -e "${GREEN}✓ Ready for distribution!${NC}"