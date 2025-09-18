package main

import (
    "bytes"
    "context"
    "crypto/tls"
    _ "embed"
    "encoding/binary"
    "encoding/json"
    "errors"
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
)

//go:embed tracker_bpfel.o
var bpfProgram []byte

// Configuration
type Config struct {
    Hostname string `json:"hostname"`
    HostIP   string `json:"hostip"`

    Elasticsearch struct {
        URLs          []string `json:"urls"`
        Index         string   `json:"index"`
        Username      string   `json:"username"`
        Password      string   `json:"password"`
        BulkSize      int      `json:"bulk_size"`
        FlushInterval int      `json:"flush_interval"`
    } `json:"elasticsearch"`

    Debug         bool `json:"debug"`
    StatsInterval int  `json:"stats_interval"`
}

// BPF Event structure - matches C struct exactly
type BPFEvent struct {
    PID       uint32
    UID       uint32
    SAddr     uint32
    DAddr     uint32
    SPort     uint16
    DPort     uint16
    Comm      [16]byte
    Direction uint8
    Action    uint8
    Bytes     uint64
    Timestamp uint64
}

// Elasticsearch document
type ConnectionDoc struct {
    Timestamp     time.Time `json:"@timestamp"`
    Hostname      string    `json:"hostname"`
    HostIP        string    `json:"host_ip"`
    ConnectionID  string    `json:"connection_id"`
    Direction     string    `json:"direction"`
    Action        string    `json:"action"`
    Protocol      string    `json:"protocol"`
    SourceIP      string    `json:"src_ip"`
    SourcePort    uint16    `json:"src_port"`
    DestIP        string    `json:"dst_ip"`
    DestPort      uint16    `json:"dst_port"`
    ProcessName   string    `json:"process_name"`
    ProcessPID    uint32    `json:"process_pid"`
    Username      string    `json:"username"`
    UID           uint32    `json:"uid"`
    BytesSent     uint64    `json:"bytes_sent,omitempty"`
    BytesReceived uint64    `json:"bytes_received,omitempty"`
    TotalBytes    uint64    `json:"total_bytes,omitempty"`
    Duration      float64   `json:"duration_seconds,omitempty"`
    ServiceName   string    `json:"service_name,omitempty"`
    Tags          []string  `json:"tags"`
}

// Active connection tracking
type ActiveConnection struct {
    StartTime     time.Time
    LastSeen      time.Time
    BytesSent     uint64
    BytesReceived uint64
    ProcessName   string
    Username      string
    PID           uint32
}

var (
    config      Config
    esClient    *elasticsearch.Client
    bulkIndexer esutil.BulkIndexer
    activeConns sync.Map
    stats       Statistics
)

type Statistics struct {
    sync.Mutex
    TotalEvents    int64
    OpenConns      int64
    ClosedConns    int64
    ActiveConns    int64
    BytesSent      uint64
    BytesReceived  uint64
    ElasticIndexed int64
    ElasticErrors  int64
}

func main() {
    var configFile string
    var showVersion bool

    flag.StringVar(&configFile, "config", "", "Config file path")
    flag.BoolVar(&config.Debug, "debug", false, "Enable debug output")
    flag.BoolVar(&showVersion, "version", false, "Show version")
    flag.Parse()

    if showVersion {
        fmt.Println("Connection Tracker v2.0 - Elasticsearch")
        os.Exit(0)
    }

    printBanner()

    if configFile != "" {
        loadConfig(configFile)
    } else {
        setDefaults()
    }

    detectHostInfo()

    if err := initElasticsearch(); err != nil {
        log.Fatalf("Failed to initialize Elasticsearch: %v", err)
    }
    defer closeElasticsearch()

    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatalf("Failed to remove memlock: %v", err)
    }

    spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfProgram))
    if err != nil {
        log.Fatalf("Failed to load BPF spec: %v", err)
    }

    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        log.Fatalf("Failed to create collection: %v", err)
    }
    defer coll.Close()

    attached := attachPrograms(coll)
    fmt.Printf("✓ Attached %d BPF programs\n", attached)

    if attached == 0 {
        log.Fatal("Failed to attach any BPF programs")
    }

    rd, err := perf.NewReader(coll.Maps["events"], os.Getpagesize()*64)
    if err != nil {
        log.Fatalf("Failed to create perf reader: %v", err)
    }
    defer rd.Close()

    fmt.Println("✓ Connection tracking active")
    fmt.Printf("✓ Sending to Elasticsearch: %v\n", config.Elasticsearch.URLs)
    fmt.Println("\nPress Ctrl+C to stop")
    fmt.Println("────────────────────────────────")

    go statsReporter()
    go connectionCleaner()

    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        for {
            record, err := rd.Read()
            if err != nil {
                if errors.Is(err, perf.ErrClosed) {
                    return
                }
                log.Printf("Error reading from perf buffer: %v", err)
                continue
            }
            handleEvent(record.RawSample)
        }
    }()

    <-sig
    shutdown()
}

func printBanner() {
    fmt.Println("╔════════════════════════════════════════╗")
    fmt.Println("║   Connection Tracker - Elasticsearch   ║")
    fmt.Println("╚════════════════════════════════════════╝")
    fmt.Println()
}

func loadConfig(path string) {
    data, err := os.ReadFile(path)
    if err != nil {
        log.Printf("Warning: Cannot read config: %v", err)
        setDefaults()
        return
    }
    if err := json.Unmarshal(data, &config); err != nil {
        log.Printf("Warning: Invalid config: %v", err)
        setDefaults()
    }
}

func setDefaults() {
    if len(config.Elasticsearch.URLs) == 0 {
        config.Elasticsearch.URLs = []string{"http://localhost:9200"}
    }
    if config.Elasticsearch.Index == "" {
        config.Elasticsearch.Index = "connections"
    }
    if config.Elasticsearch.BulkSize == 0 {
        config.Elasticsearch.BulkSize = 500
    }
    if config.Elasticsearch.FlushInterval == 0 {
        config.Elasticsearch.FlushInterval = 5
    }
    if config.StatsInterval == 0 {
        config.StatsInterval = 30
    }
}

func detectHostInfo() {
    if config.Hostname == "" {
        hostname, _ := os.Hostname()
        config.Hostname = hostname
    }

    if config.HostIP == "" {
        addrs, _ := net.InterfaceAddrs()
        for _, addr := range addrs {
            if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
                if ipnet.IP.To4() != nil {
                    config.HostIP = ipnet.IP.String()
                    break
                }
            }
        }
    }

    fmt.Printf("✓ Host: %s (%s)\n", config.Hostname, config.HostIP)
}

func initElasticsearch() error {
    cfg := elasticsearch.Config{
        Addresses: config.Elasticsearch.URLs,
    }

    if config.Elasticsearch.Username != "" {
        cfg.Username = config.Elasticsearch.Username
        cfg.Password = config.Elasticsearch.Password
    }

    cfg.Transport = &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,
        },
    }

    var err error
    esClient, err = elasticsearch.NewClient(cfg)
    if err != nil {
        return fmt.Errorf("error creating ES client: %v", err)
    }

    res, err := esClient.Info()
    if err != nil {
        return fmt.Errorf("error connecting to ES: %v", err)
    }
    defer res.Body.Close()

    bulkIndexer, err = esutil.NewBulkIndexer(esutil.BulkIndexerConfig{
        Client:        esClient,
        Index:         config.Elasticsearch.Index,
        NumWorkers:    2,
        FlushBytes:    5e6,
        FlushInterval: time.Duration(config.Elasticsearch.FlushInterval) * time.Second,
        OnError: func(ctx context.Context, err error) {
            stats.Lock()
            stats.ElasticErrors++
            stats.Unlock()
            log.Printf("Bulk indexer error: %v", err)
        },
    })

    if err != nil {
        return fmt.Errorf("error creating bulk indexer: %v", err)
    }

    return nil
}

func closeElasticsearch() {
    if bulkIndexer != nil {
        bulkIndexer.Close(context.Background())
        bulkStats := bulkIndexer.Stats()
        fmt.Printf("\nElastic Stats: Indexed=%d, Failed=%d\n",
            bulkStats.NumFlushed, bulkStats.NumFailed)
    }
}

func attachPrograms(coll *ebpf.Collection) int {
    attached := 0

    programs := []struct {
        name     string
        function string
        progType string
    }{
        {"trace_tcp_connect", "tcp_v4_connect", "kprobe"},
        {"trace_tcp_accept", "inet_csk_accept", "kretprobe"},
        {"trace_tcp_sendmsg", "tcp_sendmsg", "kprobe"},
        {"trace_tcp_close", "tcp_close", "kprobe"},
        {"trace_udp_sendmsg", "udp_sendmsg", "kprobe"},
    }

    for _, p := range programs {
        prog := coll.Programs[p.name]
        if prog == nil {
            continue
        }

        var err error
        switch p.progType {
        case "kprobe":
            _, err = link.Kprobe(p.function, prog, nil)
        case "kretprobe":
            _, err = link.Kretprobe(p.function, prog, nil)
        }

        if err != nil {
            if config.Debug {
                log.Printf("Failed to attach %s: %v", p.name, err)
            }
        } else {
            attached++
            if config.Debug {
                log.Printf("Attached %s to %s", p.name, p.function)
            }
        }
    }

    return attached
}

func handleEvent(data []byte) {
    var evt BPFEvent
    if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &evt); err != nil {
        return
    }

    doc := createConnectionDoc(evt)

    if evt.Action == 0 {
        trackConnectionOpen(doc, evt)
    } else if evt.Action == 1 {
        trackConnectionClose(doc, evt)
    } else if evt.Action == 2 {
        trackDataTransfer(doc, evt)
    }

    sendToElastic(doc)
    updateStats(evt)

    if config.Debug {
        printDebugEvent(doc)
    }
}

func createConnectionDoc(evt BPFEvent) ConnectionDoc {
    doc := ConnectionDoc{
        Timestamp:   time.Unix(0, int64(evt.Timestamp)),
        Hostname:    config.Hostname,
        HostIP:      config.HostIP,
        Protocol:    "tcp",
        ProcessName: strings.TrimRight(string(evt.Comm[:]), "\x00"),
        ProcessPID:  evt.PID,
        UID:         evt.UID,
        SourceIP:    intToIP(evt.SAddr),
        SourcePort:  evt.SPort,
        DestIP:      intToIP(evt.DAddr),
        DestPort:    evt.DPort,
        Tags:        []string{},
    }

    if evt.Direction == 0 {
        doc.Direction = "outbound"
        doc.Tags = append(doc.Tags, "outbound")
    } else {
        doc.Direction = "inbound"
        doc.Tags = append(doc.Tags, "inbound")
    }

    switch evt.Action {
    case 0:
        doc.Action = "open"
    case 1:
        doc.Action = "close"
    case 2:
        doc.Action = "data"
    }

    doc.ConnectionID = fmt.Sprintf("%s:%d->%s:%d",
        doc.SourceIP, doc.SourcePort, doc.DestIP, doc.DestPort)

    if u, err := user.LookupId(fmt.Sprintf("%d", evt.UID)); err == nil {
        doc.Username = u.Username
    } else {
        doc.Username = fmt.Sprintf("uid:%d", evt.UID)
    }

    doc.ServiceName = getServiceName(doc.DestPort)
    if doc.ServiceName != "" {
        doc.Tags = append(doc.Tags, doc.ServiceName)
    }

    if isPrivateIP(doc.DestIP) {
        doc.Tags = append(doc.Tags, "internal")
    } else {
        doc.Tags = append(doc.Tags, "external")
    }

    return doc
}

func trackConnectionOpen(doc ConnectionDoc, evt BPFEvent) {
    conn := ActiveConnection{
        StartTime:   doc.Timestamp,
        LastSeen:    doc.Timestamp,
        ProcessName: doc.ProcessName,
        Username:    doc.Username,
        PID:         doc.ProcessPID,
    }
    activeConns.Store(doc.ConnectionID, conn)

    stats.Lock()
    stats.OpenConns++
    stats.ActiveConns++
    stats.Unlock()
}

func trackConnectionClose(doc ConnectionDoc, evt BPFEvent) {
    if conn, ok := activeConns.Load(doc.ConnectionID); ok {
        activeConn := conn.(ActiveConnection)
        doc.Duration = doc.Timestamp.Sub(activeConn.StartTime).Seconds()
        activeConns.Delete(doc.ConnectionID)
    }

    stats.Lock()
    stats.ClosedConns++
    if stats.ActiveConns > 0 {
        stats.ActiveConns--
    }
    stats.Unlock()
}

func trackDataTransfer(doc ConnectionDoc, evt BPFEvent) {
    if evt.Direction == 0 {
        doc.BytesSent = evt.Bytes
    } else {
        doc.BytesReceived = evt.Bytes
    }
    doc.TotalBytes = evt.Bytes

    if conn, ok := activeConns.Load(doc.ConnectionID); ok {
        activeConn := conn.(ActiveConnection)
        activeConn.LastSeen = doc.Timestamp
        if evt.Direction == 0 {
            activeConn.BytesSent += evt.Bytes
        } else {
            activeConn.BytesReceived += evt.Bytes
        }
        activeConns.Store(doc.ConnectionID, activeConn)
    }

    stats.Lock()
    if evt.Direction == 0 {
        stats.BytesSent += evt.Bytes
    } else {
        stats.BytesReceived += evt.Bytes
    }
    stats.Unlock()
}

func sendToElastic(doc ConnectionDoc) {
    data, err := json.Marshal(doc)
    if err != nil {
        return
    }

    err = bulkIndexer.Add(
        context.Background(),
        esutil.BulkIndexerItem{
            Action: "index",
            Body:   bytes.NewReader(data),
        },
    )

    if err != nil {
        stats.Lock()
        stats.ElasticErrors++
        stats.Unlock()
    } else {
        stats.Lock()
        stats.ElasticIndexed++
        stats.Unlock()
    }
}

func updateStats(evt BPFEvent) {
    stats.Lock()
    defer stats.Unlock()
    stats.TotalEvents++
}

func printDebugEvent(doc ConnectionDoc) {
    switch doc.Action {
    case "open":
        fmt.Printf("[OPEN] %s %s:%d → %s:%d (pid:%d, user:%s)\n",
            doc.ProcessName, doc.SourceIP, doc.SourcePort,
            doc.DestIP, doc.DestPort, doc.ProcessPID, doc.Username)
    case "close":
        fmt.Printf("[CLOSE] %s:%d → %s:%d (duration:%.2fs)\n",
            doc.SourceIP, doc.SourcePort, doc.DestIP, doc.DestPort,
            doc.Duration)
    case "data":
        if doc.BytesSent > 0 {
            fmt.Printf("[DATA↑] %s:%d → %s:%d (%d bytes)\n",
                doc.SourceIP, doc.SourcePort, doc.DestIP, doc.DestPort, doc.BytesSent)
        }
        if doc.BytesReceived > 0 {
            fmt.Printf("[DATA↓] %s:%d ← %s:%d (%d bytes)\n",
                doc.SourceIP, doc.SourcePort, doc.DestIP, doc.DestPort, doc.BytesReceived)
        }
    }
}

func statsReporter() {
    ticker := time.NewTicker(time.Duration(config.StatsInterval) * time.Second)
    defer ticker.Stop()

    for range ticker.C {
        printStats()
    }
}

func printStats() {
    stats.Lock()
    defer stats.Unlock()

    fmt.Printf("\n📊 Stats [%s]\n", time.Now().Format("15:04:05"))
    fmt.Printf("├─ Events: %d total\n", stats.TotalEvents)
    fmt.Printf("├─ Connections: %d active, %d opened, %d closed\n",
        stats.ActiveConns, stats.OpenConns, stats.ClosedConns)
    fmt.Printf("├─ Volume: ↑ %s, ↓ %s\n",
        formatBytes(stats.BytesSent), formatBytes(stats.BytesReceived))
    fmt.Printf("└─ Elastic: %d indexed, %d errors\n",
        stats.ElasticIndexed, stats.ElasticErrors)
}

func connectionCleaner() {
    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()

    for range ticker.C {
        now := time.Now()
        activeConns.Range(func(key, value interface{}) bool {
            conn := value.(ActiveConnection)
            if now.Sub(conn.LastSeen) > 5*time.Minute {
                activeConns.Delete(key)
                stats.Lock()
                if stats.ActiveConns > 0 {
                    stats.ActiveConns--
                }
                stats.Unlock()
            }
            return true
        })
    }
}

func shutdown() {
    fmt.Println("\nShutting down...")
    printStats()

    count := 0
    activeConns.Range(func(key, value interface{}) bool {
        count++
        return true
    })
    fmt.Printf("\nActive connections at shutdown: %d\n", count)
    fmt.Println("✓ Shutdown complete")
}

func intToIP(addr uint32) string {
    ip := make(net.IP, 4)
    binary.LittleEndian.PutUint32(ip, addr)
    return ip.String()
}

func isPrivateIP(ip string) bool {
    privateRanges := []string{
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
        "192.168.", "127.",
    }

    for _, prefix := range privateRanges {
        if strings.HasPrefix(ip, prefix) {
            return true
        }
    }
    return false
}

func getServiceName(port uint16) string {
    services := map[uint16]string{
        22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 443: "https", 445: "smb",
        3306: "mysql", 5432: "postgresql", 6379: "redis",
        9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
        3389: "rdp", 5900: "vnc", 8080: "http-alt",
    }

    if name, ok := services[port]; ok {
        return name
    }
    return ""
}

func formatBytes(bytes uint64) string {
    const (
        KB = 1024
        MB = KB * 1024
        GB = MB * 1024
    )

    switch {
    case bytes >= GB:
        return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
    case bytes >= MB:
        return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
    case bytes >= KB:
        return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
    default:
        return fmt.Sprintf("%d B", bytes)
    }
}