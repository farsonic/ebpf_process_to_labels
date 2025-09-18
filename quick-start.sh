#!/bin/bash

# Quick start script for Connection Tracker with Elasticsearch
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}╔═══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Connection Tracker - Quick Start      ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════╝${NC}"
echo ""

# Function to check if Elasticsearch is running
check_elasticsearch() {
    echo -n "Checking Elasticsearch... "
    
    if curl -s -o /dev/null -w "%{http_code}" localhost:9200 | grep -q "200\|401"; then
        echo -e "${GREEN}✓ Running${NC}"
        return 0
    else
        echo -e "${RED}✗ Not found${NC}"
        return 1
    fi
}

# Function to start Elasticsearch with Docker
start_elasticsearch() {
    echo ""
    echo "Elasticsearch not found. Would you like to start it with Docker?"
    read -p "Start Elasticsearch container? (y/n) " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Starting Elasticsearch..."
        docker run -d \
            --name elasticsearch \
            -p 9200:9200 \
            -p 9300:9300 \
            -e "discovery.type=single-node" \
            -e "xpack.security.enabled=false" \
            -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" \
            docker.elastic.co/elasticsearch/elasticsearch:8.11.0
        
        echo "Waiting for Elasticsearch to start..."
        sleep 10
        
        # Wait for Elasticsearch to be ready
        for i in {1..30}; do
            if curl -s localhost:9200 >/dev/null 2>&1; then
                echo -e "${GREEN}✓ Elasticsearch started${NC}"
                break
            fi
            sleep 2
        done
    fi
}

# Create Elasticsearch index template
setup_elasticsearch() {
    echo ""
    echo "Setting up Elasticsearch index template..."
    
    curl -s -X PUT "localhost:9200/_index_template/connections" \
        -H 'Content-Type: application/json' \
        -d '{
          "index_patterns": ["connections*"],
          "template": {
            "settings": {
              "number_of_shards": 1,
              "number_of_replicas": 0,
              "refresh_interval": "5s"
            },
            "mappings": {
              "properties": {
                "@timestamp": {"type": "date"},
                "hostname": {"type": "keyword"},
                "host_ip": {"type": "ip"},
                "connection_id": {"type": "keyword"},
                "direction": {"type": "keyword"},
                "action": {"type": "keyword"},
                "src_ip": {"type": "ip"},
                "dst_ip": {"type": "ip"},
                "src_port": {"type": "integer"},
                "dst_port": {"type": "integer"},
                "process_name": {"type": "keyword"},
                "username": {"type": "keyword"},
                "bytes_sent": {"type": "long"},
                "bytes_received": {"type": "long"},
                "duration_seconds": {"type": "float"},
                "service_name": {"type": "keyword"},
                "tags": {"type": "keyword"}
              }
            }
          }
        }' >/dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Index template created${NC}"
    else
        echo -e "${YELLOW}⚠ Could not create index template${NC}"
    fi
}

# Build the tracker
build_tracker() {
    echo ""
    echo "Building Connection Tracker..."
    
    if [ -f "./build.sh" ]; then
        ./build.sh
    else
        echo -e "${RED}Error: build.sh not found${NC}"
        exit 1
    fi
}

# Configure tracker
configure_tracker() {
    echo ""
    echo "Configuring Connection Tracker..."
    
    # Get Elasticsearch credentials if needed
    ES_USER=""
    ES_PASS=""
    
    read -p "Does Elasticsearch require authentication? (y/n) " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        read -p "Username: " ES_USER
        read -s -p "Password: " ES_PASS
        echo ""
    fi
    
    # Create config
    cat > config.json << EOF
{
    "hostname": "$(hostname)",
    "hostip": "",
    "elasticsearch": {
        "urls": ["http://localhost:9200"],
        "index": "connections",
        "username": "$ES_USER",
        "password": "$ES_PASS",
        "bulk_size": 500,
        "flush_interval": 5
    },
    "debug": true,
    "stats_interval": 30,
    "track_volume": true
}
EOF
    
    echo -e "${GREEN}✓ Configuration created${NC}"
}

# Run the tracker
run_tracker() {
    echo ""
    echo -e "${CYAN}Starting Connection Tracker...${NC}"
    echo "────────────────────────────────────"
    echo ""
    
    if [ ! -f "./connection-tracker" ]; then
        echo -e "${RED}Error: connection-tracker binary not found${NC}"
        echo "Please run: ./build.sh"
        exit 1
    fi
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        echo "Switching to root (required for eBPF)..."
        sudo ./connection-tracker --config config.json --debug
    else
        ./connection-tracker --config config.json --debug
    fi
}

# Test mode - generate some traffic
test_mode() {
    echo ""
    echo "Generating test traffic..."
    echo "Run these commands in another terminal:"
    echo ""
    echo "  curl https://www.google.com"
    echo "  ping -c 4 8.8.8.8"
    echo "  nc -zv scanme.nmap.org 22"
    echo "  wget https://www.example.com"
    echo ""
}

# Main menu
main_menu() {
    echo ""
    echo "Select an option:"
    echo "  1) Quick setup (build + configure + run)"
    echo "  2) Build only"
    echo "  3) Configure only"
    echo "  4) Run tracker"
    echo "  5) Setup Elasticsearch"
    echo "  6) Test mode"
    echo ""
    read -p "Choice (1-6): " choice
    
    case $choice in
        1)
            check_elasticsearch || start_elasticsearch
            setup_elasticsearch
            build_tracker
            configure_tracker
            run_tracker
            ;;
        2)
            build_tracker
            ;;
        3)
            configure_tracker
            ;;
        4)
            run_tracker
            ;;
        5)
            check_elasticsearch || start_elasticsearch
            setup_elasticsearch
            ;;
        6)
            test_mode
            ;;
        *)
            echo "Invalid choice"
            ;;
    esac
}

# Check if we're running with an argument
if [ "$1" == "run" ]; then
    run_tracker
elif [ "$1" == "build" ]; then
    build_tracker
elif [ "$1" == "setup" ]; then
    check_elasticsearch || start_elasticsearch
    setup_elasticsearch
    build_tracker
    configure_tracker
else
    main_menu
fi