//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 tracker tracker.bpf.c -- -I.

package main

import (
    "bytes"
    "context"
    "crypto/tls"
    _ "embed"
    "encoding/binary"
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "net"
    "net/http"
    "os"
    "os/signal"
    "os/user"
    "strings"
    "sync"
    "syscall"
    "time"
    
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/perf"
    "github.com/cilium/ebpf/rlimit"
    "github.com/elastic/go-elasticsearch/v8"
    "github.com/elastic/go-elasticsearch/v8/esutil"
    "github.com/go-redis/redis/v8"
)

//go:embed tracker_bpfel.o
var bpfProgram []byte

// Configuration structure supporting multiple backends
type Config struct {
    // Host information
    HostIP       string `json:"hostip"`
    Hostname     string `json:"hostname"`
    
    // PSM Configuration (optional)
    PSM struct {
        Enabled     bool   `json:"enabled"`
        IPAddress   string `json:"ip_address"`
        Username    string `json:"username"`
        Password    string `json:"password"`
        PushInterval int   `json:"push_interval"` // seconds, default 30
    } `json:"psm"`
    
    // Elasticsearch Configuration (optional)
    Elastic struct {
        Enabled      bool     `json:"enabled"`
        URLs         []string `json:"urls"`          // Multiple ES nodes
        Index        string   `json:"index"`         // Default: "connections"
        Username     string   `json:"username"`      // Basic auth
        Password     string   `json:"password"`      // Basic auth
        APIKey       string   `json:"api_key"`       // API key auth
        CloudID      string   `json:"cloud_id"`      // Elastic Cloud
        BulkSize     int      `json:"bulk_size"`     // Default: 500
        FlushInterval int     `json:"flush_interval"` // seconds, default 5
        EnableSSL    bool     `json:"enable_ssl"`
        VerifySSL    bool     `json:"verify_ssl"`
    } `json:"elastic"`
    
    // Redis Configuration (optional)
    Redis struct {
        Enabled  bool   `json:"enabled"`
        Address  string `json:"address"`  // Default: "localhost:6379"
        Password string `json:"password"`
        DB       int    `json:"db"`
        TTL      int    `json:"ttl"` // seconds, default 3600
    } `json:"redis"`
    
    // Local storage (always enabled as fallback)
    Local struct {
        MaxEvents    int    `json:"max_events"`     // Max in-memory events, default 10000
        LogFile      string `json:"log_file"`       // Optional file logging
        LogRotateSize int   `json:"log_rotate_size"` // MB, default 100
    } `json:"local"`
    
    // General settings
    Debug            bool     `json:"debug"`
    StatsInterval    int      `json:"stats_interval"`    // seconds, default 60
    FilterProcesses  []string `json:"filter_processes"`  // Process names to filter out
    FilterPorts      []int    `json:"filter_ports"`      // Ports to filter out
}

// Event structure from BPF
type Event struct {
    PID       uint32
    UID       uint32
    SAddr     uint32
    DAddr     uint32
    SPort     uint16
    DPort     uint16
    Comm      [16]byte
    Direction uint8
}

// Connection event for storage/sending
type ConnectionEvent struct {
    Timestamp   time.Time `json:"@timestamp"`
    Hostname    string    `json:"hostname"`
    HostIP      string    `json:"host_ip"`
    Direction   string    `json:"direction"`
    Protocol    string    `json:"protocol"`
    SourceIP    string    `json:"src_ip"`
    SourcePort  uint16    `json:"src_port"`
    DestIP      string    `json:"dst_ip"`
    DestPort    uint16    `json:"dst_port"`
    ProcessName string    `json:"process_name"`
    ProcessPID  uint32    `json:"process_pid"`
    Username    string    `json:"username"`
    UID         uint32    `json:"uid"`
    
    // Optional enrichments
    ServiceName string            `json:"service_name,omitempty"`
    Tags        []string          `json:"tags,omitempty"`
    Metadata    map[string]string `json:"metadata,omitempty"`
}

// Global state
var (
    config         Config
    elasticClient  *ElasticClient
    redisClient    *redis.Client
    psmClient      *PSMClient
    memoryStore    sync.Map
    stats          Statistics
    ctx            = context.Background()
)

// Statistics tracking
type Statistics struct {
    sync.Mutex
    Total       int64
    Inbound     int64
    Outbound    int64
    Filtered    int64
    ElasticSent int64
    PSMSent     int64
    Errors      int64
}

// Elasticsearch client wrapper
type ElasticClient struct {
    client   *elasticsearch.Client
    indexer  esutil.BulkIndexer
    enabled  bool
}

// PSM client wrapper
type PSMClient struct {
    enabled      bool
    url          string
    username     string
    password     string
    authToken    string
    tokenMutex   sync.RWMutex
    pushInterval time.Duration
    httpClient   *http.Client
}

func main() {
    // Parse command-line arguments
    var configFile string
    var showVersion bool
    
    flag.StringVar(&configFile, "config", "", "Config file path")
    flag.StringVar(&configFile, "c", "", "Config file path (short)")
    flag.BoolVar(&config.Debug, "debug", false, "Enable debug output")
    flag.BoolVar(&config.Debug, "d", false, "Enable debug (short)")
    flag.BoolVar(&showVersion, "version", false, "Show version")
    flag.BoolVar(&showVersion, "v", false, "Show version (short)")
    
    // Backend overrides
    flag.BoolVar(&config.PSM.Enabled, "enable-psm", false, "Enable PSM")
    flag.BoolVar(&config.Elastic.Enabled, "enable-elastic", false, "Enable Elasticsearch")
    flag.BoolVar(&config.Redis.Enabled, "enable-redis", false, "Enable Redis")
    
    flag.Parse()
    
    if showVersion {
        fmt.Println("Connection Tracker v2.0.0 - eBPF Network Monitor")
        fmt.Println("Supports: PSM, Elasticsearch, Redis, Local storage")
        os.Exit(0)
    }
    
    printBanner()
    
    // Load configuration
    if err := loadConfig(configFile); err != nil {
        log.Printf("Warning: %v, using defaults", err)
    }
    
    // Auto-detect host info if not set
    detectHostInfo()
    
    // Show active backends
    showBackendStatus()
    
    // Initialize backends
    initializeBackends()
    
    // Setup eBPF
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatalf("Failed to remove memlock: %v", err)
    }
    
    spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfProgram))
    if err != nil {
        log.Fatalf("Failed to load BPF: %v", err)
    }
    
    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        log.Fatalf("Failed to create collection: %v", err)
    }
    defer coll.Close()
    
    // Attach programs
    attached := attachPrograms(coll)
    if attached == 0 {
        log.Fatal("Failed to attach any BPF programs")
    }
    fmt.Printf("✓ Attached %d BPF programs\n", attached)
    
    // Setup perf reader
    rd, err := perf.NewReader(coll.Maps["events"], os.Getpagesize())
    if err != nil {
        log.Fatalf("Failed to create perf reader: %v", err)
    }
    defer rd.Close()
    
    fmt.Println("✓ Connection tracking active")
    fmt.Println("\nPress Ctrl+C to stop")
    fmt.Println("────────────────────────────────")
    
    // Start background workers
    startBackgroundWorkers()
    
    // Signal handler
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
    
    // Main event loop
    eventLoop := func() {
        for {
            record, err := rd.Read()
            if err != nil {
                return
            }
            handleEvent(record.RawSample)
        }
    }
    
    go eventLoop()
    
    // Wait for shutdown
    <-sig
    
    // Cleanup
    fmt.Println("\n────────────────────────────────")
    shutdown()
}

func printBanner() {
    fmt.Println("╔═══════════════════════════════════════════╗")
    fmt.Println("║   Connection Tracker v2.0 - Multi-Backend ║")
    fmt.Println("╚═══════════════════════════════════════════╝")
    fmt.Println()
}

func loadConfig(configFile string) error {
    // Set defaults first
    setDefaults()
    
    // Try to load config file
    searchPaths := []string{}
    if configFile != "" {
        searchPaths = append(searchPaths, configFile)
    }
    searchPaths = append(searchPaths, 
        "config.json",
        "/etc/connection-tracker/config.json",
        "$HOME/.connection-tracker/config.json",
    )
    
    for _, path := range searchPaths {
        path = os.ExpandEnv(path)
        if data, err := os.ReadFile(path); err == nil {
            if err := json.Unmarshal(data, &config); err == nil {
                fmt.Printf("✓ Config loaded from %s\n", path)
                return nil
            }
        }
    }
    
    return fmt.Errorf("no config file found")
}

func setDefaults() {
    // Set reasonable defaults
    if config.Elastic.Index == "" {
        config.Elastic.Index = "connections"
    }
    if config.Elastic.BulkSize == 0 {
        config.Elastic.BulkSize = 500
    }
    if config.Elastic.FlushInterval == 0 {
        config.Elastic.FlushInterval = 5
    }
    
    if config.PSM.PushInterval == 0 {
        config.PSM.PushInterval = 30
    }
    
    if config.Redis.Address == "" {
        config.Redis.Address = "localhost:6379"
    }
    if config.Redis.TTL == 0 {
        config.Redis.TTL = 3600
    }
    
    if config.Local.MaxEvents == 0 {
        config.Local.MaxEvents = 10000
    }
    
    if config.StatsInterval == 0 {
        config.StatsInterval = 60
    }
}

func detectHostInfo() {
    // Auto-detect hostname if not set
    if config.Hostname == "" {
        if hostname, err := os.Hostname(); err == nil {
            config.Hostname = hostname
        } else {
            config.Hostname = "unknown"
        }
    }
    
    // Auto-detect host IP if not set
    if config.HostIP == "" {
        if addrs, err := net.InterfaceAddrs(); err == nil {
            for _, addr := range addrs {
                if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
                    if ipnet.IP.To4() != nil {
                        config.HostIP = ipnet.IP.String()
                        break
                    }
                }
            }
        }
        if config.HostIP == "" {
            config.HostIP = "127.0.0.1"
        }
    }
    
    fmt.Printf("✓ Host: %s (%s)\n", config.Hostname, config.HostIP)
}

func showBackendStatus() {
    fmt.Println("\nActive Backends:")
    fmt.Println("─────────────────")
    
    activeCount := 0
    
    if config.Elastic.Enabled {
        fmt.Printf("✓ Elasticsearch: %v\n", config.Elastic.URLs)
        activeCount++
    } else {
        fmt.Println("✗ Elasticsearch: Disabled")
    }
    
    if config.PSM.Enabled {
        fmt.Printf("✓ PSM: %s\n", config.PSM.IPAddress)
        activeCount++
    } else {
        fmt.Println("✗ PSM: Disabled")
    }
    
    if config.Redis.Enabled {
        fmt.Printf("✓ Redis: %s\n", config.Redis.Address)
        activeCount++
    } else {
        fmt.Println("✗ Redis: Disabled")
    }
    
    fmt.Printf("✓ Local Memory: Always active (max %d events)\n", config.Local.MaxEvents)
    
    if config.Local.LogFile != "" {
        fmt.Printf("✓ File Logging: %s\n", config.Local.LogFile)
    }
    
    if activeCount == 0 {
        fmt.Println("\n⚠ Warning: No external backends enabled!")
        fmt.Println("  Events will only be stored in memory")
    }
    
    fmt.Println()
}

func initializeBackends() {
    var wg sync.WaitGroup
    
    // Initialize Elasticsearch
    if config.Elastic.Enabled {
        wg.Add(1)
        go func() {
            defer wg.Done()
            if client, err := NewElasticClient(config); err == nil {
                elasticClient = client
                fmt.Println("✓ Elasticsearch connected")
            } else {
                log.Printf("Warning: Elasticsearch failed: %v", err)
                config.Elastic.Enabled = false
            }
        }()
    }
    
    // Initialize PSM
    if config.PSM.Enabled {
        wg.Add(1)
        go func() {
            defer wg.Done()
            psmClient = NewPSMClient(config)
            if err := psmClient.TestConnection(); err == nil {
                fmt.Println("✓ PSM connected")
            } else {
                log.Printf("Warning: PSM connection failed: %v", err)
                config.PSM.Enabled = false
            }
        }()
    }
    
    // Initialize Redis
    if config.Redis.Enabled {
        wg.Add(1)
        go func() {
            defer wg.Done()
            redisClient = redis.NewClient(&redis.Options{
                Addr:     config.Redis.Address,
                Password: config.Redis.Password,
                DB:       config.Redis.DB,
            })
            
            if _, err := redisClient.Ping(ctx).Result(); err == nil {
                fmt.Println("✓ Redis connected")
            } else {
                log.Printf("Warning: Redis connection failed: %v", err)
                config.Redis.Enabled = false
            }
        }()
    }
    
    wg.Wait()
}

func attachPrograms(coll *ebpf.Collection) int {
    attached := 0
    
    // Try kprobes
    for name, fn := range map[string]string{
        "trace_tcp_connect": "tcp_v4_connect",
        "trace_tcp_accept":  "inet_csk_accept",
    } {
        if prog := coll.Programs[name]; prog != nil {
            if l, err := link.Kprobe(fn, prog, nil); err == nil {
                defer l.Close()
                attached++
            }
        }
    }
    
    // Try tracepoint as fallback
    if attached == 0 {
        if prog := coll.Programs["trace_connect_syscall"]; prog != nil {
            if l, err := link.Tracepoint("syscalls", "sys_enter_connect", prog, nil); err == nil {
                defer l.Close()
                attached++
            }
        }
    }
    
    return attached
}

func handleEvent(data []byte) {
    var evt Event
    if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
        stats.Lock()
        stats.Errors++
        stats.Unlock()
        return
    }
    
    // Convert to ConnectionEvent
    connEvent := createConnectionEvent(evt)
    
    // Apply filters
    if shouldFilter(connEvent) {
        stats.Lock()
        stats.Filtered++
        stats.Unlock()
        return
    }
    
    // Update statistics
    updateStats(connEvent)
    
    // Send to all enabled backends
    sendToBackends(connEvent)
    
    // Debug output
    if config.Debug {
        printDebugEvent(connEvent)
    }
}

func createConnectionEvent(evt Event) ConnectionEvent {
    return ConnectionEvent{
        Timestamp:   time.Now(),
        Hostname:    config.Hostname,
        HostIP:      config.HostIP,
        Direction:   getDirection(evt.Direction),
        Protocol:    "tcp",
        SourceIP:    intToIP(evt.SAddr),
        SourcePort:  evt.SPort,
        DestIP:      intToIP(evt.DAddr),
        DestPort:    ntohs(evt.DPort),
        ProcessName: strings.TrimRight(string(evt.Comm[:]), "\x00"),
        ProcessPID:  evt.PID,
        Username:    uidToUser(evt.UID),
        UID:         evt.UID,
        ServiceName: getServiceName(ntohs(evt.DPort)),
        Tags:        generateTags(evt),
    }
}

func shouldFilter(evt ConnectionEvent) bool {
    // Filter loopback
    if evt.SourceIP == "127.0.0.1" && evt.DestIP == "127.0.0.1" {
        return true
    }
    
    // Filter processes
    for _, proc := range config.FilterProcesses {
        if evt.ProcessName == proc {
            return true
        }
    }
    
    // Filter ports
    for _, port := range config.FilterPorts {
        if int(evt.DestPort) == port {
            return true
        }
    }
    
    return false
}

func sendToBackends(evt ConnectionEvent) {
    var wg sync.WaitGroup
    
    // Send to Elasticsearch
    if elasticClient != nil && elasticClient.enabled {
        wg.Add(1)
        go func() {
            defer wg.Done()
            if err := elasticClient.SendEvent(evt); err != nil {
                log.Printf("Elastic error: %v", err)
            } else {
                stats.Lock()
                stats.ElasticSent++
                stats.Unlock()
            }
        }()
    }
    
    // Store in Redis
    if config.Redis.Enabled && redisClient != nil {
        wg.Add(1)
        go func() {
            defer wg.Done()
            key := fmt.Sprintf("%s:%s:%d", evt.Direction, evt.ProcessName, evt.ProcessPID)
            data, _ := json.Marshal(evt)
            redisClient.Set(ctx, key, data, time.Duration(config.Redis.TTL)*time.Second)
        }()
    }
    
    // Store in memory (always)
    storeInMemory(evt)
    
    // Log to file if configured
    if config.Local.LogFile != "" {
        logToFile(evt)
    }
    
    wg.Wait()
}

func startBackgroundWorkers() {
    // Stats reporter
    go func() {
        ticker := time.NewTicker(time.Duration(config.StatsInterval) * time.Second)
        defer ticker.Stop()
        
        for range ticker.C {
            printStats()
        }
    }()
    
    // PSM pusher
    if psmClient != nil && psmClient.enabled {
        go psmClient.StartPusher()
    }
}

func printStats() {
    stats.Lock()
    defer stats.Unlock()
    
    if config.Debug || config.StatsInterval > 0 {
        fmt.Printf("\n📊 Stats: Total=%d (In=%d Out=%d) Filtered=%d Elastic=%d PSM=%d Errors=%d\n",
            stats.Total, stats.Inbound, stats.Outbound, 
            stats.Filtered, stats.ElasticSent, stats.PSMSent, stats.Errors)
    }
}

func shutdown() {
    fmt.Println("Shutting down...")
    
    // Close Elasticsearch
    if elasticClient != nil {
        elasticClient.Close()
    }
    
    // Close Redis
    if redisClient != nil {
        redisClient.Close()
    }
    
    // Final stats
    printStats()
    fmt.Println("✓ Shutdown complete")
}

// Helper functions
func getDirection(dir uint8) string {
    if dir == 0 {
        return "outbound"
    }
    return "inbound"
}

func intToIP(addr uint32) string {
    ip := make(net.IP, 4)
    binary.LittleEndian.PutUint32(ip, addr)
    return ip.String()
}

func ntohs(port uint16) uint16 {
    return (port>>8)&0xff | (port&0xff)<<8
}

func uidToUser(uid uint32) string {
    if u, err := user.LookupId(fmt.Sprintf("%d", uid)); err == nil {
        return u.Username
    }
    return fmt.Sprintf("uid:%d", uid)
}

func getServiceName(port uint16) string {
    services := map[uint16]string{
        22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 443: "https", 3306: "mysql", 5432: "postgresql",
        6379: "redis", 9200: "elasticsearch", 27017: "mongodb",
    }
    
    if name, ok := services[port]; ok {
        return name
    }
    return fmt.Sprintf("port-%d", port)
}

func generateTags(evt Event) []string {
    tags := []string{}
    
    if evt.Direction == 0 {
        tags = append(tags, "outbound")
    } else {
        tags = append(tags, "inbound")
    }
    
    // Add more tags based on port, IP, etc.
    
    return tags
}

func updateStats(evt ConnectionEvent) {
    stats.Lock()
    defer stats.Unlock()
    
    stats.Total++
    if evt.Direction == "inbound" {
        stats.Inbound++
    } else {
        stats.Outbound++
    }
}

func printDebugEvent(evt ConnectionEvent) {
    fmt.Printf("[%s] %s %s:%d → %s:%d (pid:%d, user:%s)\n",
        evt.Direction[:3],
        evt.ProcessName,
        evt.SourceIP, evt.SourcePort,
        evt.DestIP, evt.DestPort,
        evt.ProcessPID, evt.Username)
}

func storeInMemory(evt ConnectionEvent) {
    key := fmt.Sprintf("%d-%d", evt.ProcessPID, time.Now().UnixNano())
    memoryStore.Store(key, evt)
    
    // Cleanup old events if over limit
    // (implement circular buffer or LRU if needed)
}

func logToFile(evt ConnectionEvent) {
    // Implement file logging with rotation
    // (can use lumberjack or similar)
}