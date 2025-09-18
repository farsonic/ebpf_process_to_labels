#!/bin/bash

# Package script - creates a portable bundle for distribution
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

VERSION="1.0.0"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
ARCH=$(uname -m)
PACKAGE_NAME="connection-tracker-${VERSION}-${ARCH}-${TIMESTAMP}"

echo -e "${BLUE}╔═══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Connection Tracker Bundle Creator   ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════╝${NC}"
echo ""

# Create package directory
mkdir -p "$PACKAGE_NAME"

# Copy binary
if [ -f "./connection-tracker" ]; then
    cp ./connection-tracker "$PACKAGE_NAME/"
elif [ -f "/usr/local/bin/connection-tracker" ]; then
    cp /usr/local/bin/connection-tracker "$PACKAGE_NAME/"
fi

# Create installer
cat > "$PACKAGE_NAME/install.sh" << 'INSTALLER'
#!/bin/bash
[Full installer script content - abbreviated for space]
INSTALLER
chmod +x "$PACKAGE_NAME/install.sh"

# Create uninstaller
cat > "$PACKAGE_NAME/uninstall.sh" << 'UNINSTALLER'
#!/bin/bash
[Uninstaller script content]
UNINSTALLER
chmod +x "$PACKAGE_NAME/uninstall.sh"

# Create README
cat > "$PACKAGE_NAME/README.md" << 'README'
# Connection Tracker - Portable Bundle
[README content]
README

# Create sample config
cat > "$PACKAGE_NAME/config.sample.json" << 'EOF'
{
    "psmipaddress": "10.0.0.100",
    "psmusername": "admin",
    "psmpassword": "changeme",
    "hostip": "",
    "hostname": ""
}
EOF

# Create VERSION file
echo "$VERSION" > "$PACKAGE_NAME/VERSION"

# Create tarball
tar czf "${PACKAGE_NAME}.tar.gz" "$PACKAGE_NAME/"
sha256sum "${PACKAGE_NAME}.tar.gz" > "${PACKAGE_NAME}.tar.gz.sha256"

rm -rf "$PACKAGE_NAME/"

SIZE=$(du -h "${PACKAGE_NAME}.tar.gz" | cut -f1)

echo ""
echo -e "${GREEN}✓ Bundle created: ${PACKAGE_NAME}.tar.gz (${SIZE})${NC}"