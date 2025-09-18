//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64,arm64 tracker tracker.bpf.c -- -I.

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
)

//go:embed tracker_bpfel.o
var bpfProgram []byte

// Configuration structure
type Config struct {
    Hostname string `json:"hostname"`
    HostIP   string `json:"hostip"`

    PSM struct {
        Enabled     bool   `json:"enabled"`
        IPAddress   string `json:"ip_address"`
        Username    string `json:"username"`
        Password    string `json:"password"`
    } `json:"psm"`

    Elastic struct {
        Enabled  bool     `json:"enabled"`
        URLs     []string `json:"urls"`
        Index    string   `json:"index"`
        Username string   `json:"username"`
        Password string   `json:"password"`
    } `json:"elastic"`

    Redis struct {
        Enabled bool `json:"enabled"`
        Address string `json:"address"`
    } `json:"redis"`

    Local struct {
        MaxEvents int    `json:"max_events"`
        LogFile   string `json:"log_file"`
    } `json:"local"`

    Debug         bool `json:"debug"`
    StatsInterval int  `json:"stats_interval"`
}

// Event structure - MUST match C struct exactly (37 bytes packed)
type Event struct {
    PID       uint32    // 4 bytes
    UID       uint32    // 4 bytes
    SAddr     uint32    // 4 bytes
    DAddr     uint32    // 4 bytes
    SPort     uint16    // 2 bytes
    DPort     uint16    // 2 bytes
    Comm      [16]byte  // 16 bytes
    Direction uint8     // 1 byte
    // Total: 37 bytes
}

var (
    config    Config
    stats     Statistics
    logFile   *os.File
    ctx       = context.Background()
)

type Statistics struct {
    sync.Mutex
    Total    int64
    Inbound  int64
    Outbound int64
}

func main() {
    var configFile string

    flag.StringVar(&configFile, "config", "", "Config file path")
    flag.BoolVar(&config.Debug, "debug", false, "Enable debug output")
    flag.Parse()

    printBanner()

    // Load config
    loadConfig(configFile)

    // Setup log file if configured
    if config.Local.LogFile != "" {
        var err error
        logFile, err = os.OpenFile(config.Local.LogFile,
            os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
        if err != nil {
            log.Printf("Warning: Cannot open log file: %v", err)
        } else {
            defer logFile.Close()
        }
    }

    // Setup eBPF
    if err := rlimit.RemoveMemlock(); err != nil {
        log.Fatalf("Failed to remove memlock: %v", err)
    }

    spec, err := ebpf.Lo