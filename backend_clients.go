package main

import (
    "bytes"
    "context"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "sync"
    "time"

    "github.com/elastic/go-elasticsearch/v8"
    "github.com/elastic/go-elasticsearch/v8/esutil"
)

// NewElasticClient creates and configures Elasticsearch client
func NewElasticClient(config Config) (*ElasticClient, error) {
    cfg := elasticsearch.Config{
        Addresses: config.Elastic.URLs,
    }
    
    // Add authentication if provided
    if config.Elastic.Username != "" {
        cfg.Username = config.Elastic.Username
        cfg.Password = config.Elastic.Password
    } else if config.Elastic.APIKey != "" {
        cfg.APIKey = config.Elastic.APIKey
    } else if config.Elastic.CloudID != "" {
        cfg.CloudID = config.Elastic.CloudID
    }
    
    // Configure SSL/TLS
    if config.Elastic.EnableSSL {
        cfg.Transport = &http.Transport{
            TLSClientConfig: &tls.Config{
                InsecureSkipVerify: !config.Elastic.VerifySSL,
            },
        }
    }
    
    // Create client
    client, err := elasticsearch.NewClient(cfg)
    if err != nil {
        return nil, fmt.Errorf("error creating Elasticsearch client: %v", err)
    }
    
    // Test connection
    res, err := client.Info()
    if err != nil {
        return nil, fmt.Errorf("error connecting to Elasticsearch: %v", err)
    }
    defer res.Body.Close()
    
    // Create bulk indexer
    bulkSize := config.Elastic.BulkSize
    if bulkSize == 0 {
        bulkSize = 500
    }
    
    flushInterval := config.Elastic.FlushInterval
    if flushInterval == 0 {
        flushInterval = 5
    }
    
    indexer, err := esutil.NewBulkIndexer(esutil.BulkIndexerConfig{
        Client:        client,
        Index:         config.Elastic.Index,
        NumWorkers:    2,
        FlushBytes:    int(5e6),  // 5MB
        FlushInterval: time.Duration(flushInterval) * time.Second,
        OnError: func(ctx context.Context, err error) {
            log.Printf("Elasticsearch bulk indexer error: %v", err)
        },
    })
    
    if err != nil {
        return nil, fmt.Errorf("error creating bulk indexer: %v", err)
    }
    
    return &ElasticClient{
        client:  client,
        indexer: indexer,
        enabled: true,
    }, nil
}

// SendEvent sends a connection event to Elasticsearch
func (ec *ElasticClient) SendEvent(evt ConnectionEvent) error {
    if !ec.enabled {
        return nil
    }
    
    data, err := json.Marshal(evt)
    if err != nil {
        return err
    }
    
    return ec.indexer.Add(
        context.Background(),
        esutil.BulkIndexerItem{
            Action: "index",
            Body:   bytes.NewReader(data),
        },
    )
}

// Close flushes and closes the Elasticsearch client
func (ec *ElasticClient) Close() error {
    if ec.indexer != nil {
        ec.indexer.Close(context.Background())
    }
    return nil
}

// NewPSMClient creates a PSM client
func NewPSMClient(config Config) *PSMClient {
    return &PSMClient{
        enabled:      config.PSM.Enabled,
        url:          fmt.Sprintf("https://%s", config.PSM.IPAddress),
        username:     config.PSM.Username,
        password:     config.PSM.Password,
        pushInterval: time.Duration(config.PSM.PushInterval) * time.Second,
        httpClient: &http.Client{
            Timeout: 30 * time.Second,
            Transport: &http.Transport{
                TLSClientConfig: &tls.Config{
                    InsecureSkipVerify: true, // PSM often uses self-signed certs
                },
            },
        },
    }
}

// TestConnection tests PSM connectivity
func (pc *PSMClient) TestConnection() error {
    if !pc.enabled {
        return nil
    }
    
    // Authenticate first
    if err := pc.authenticate(); err != nil {
        return err
    }
    
    // Test API endpoint
    req, err := http.NewRequest("GET", pc.url+"/api/v1/status", nil)
    if err != nil {
        return err
    }
    
    pc.tokenMutex.RLock()
    req.Header.Set("Authorization", "Bearer "+pc.authToken)
    pc.tokenMutex.RUnlock()
    
    resp, err := pc.httpClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("PSM API returned status %d", resp.StatusCode)
    }
    
    return nil
}

// authenticate gets PSM auth token
func (pc *PSMClient) authenticate() error {
    authPayload := map[string]string{
        "username": pc.username,
        "password": pc.password,
    }
    
    data, err := json.Marshal(authPayload)
    if err != nil {
        return err
    }
    
    req, err := http.NewRequest("POST", pc.url+"/api/v1/auth", bytes.NewBuffer(data))
    if err != nil {
        return err
    }
    
    req.Header.Set("Content-Type", "application/json")
    
    resp, err := pc.httpClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("authentication failed: %d - %s", resp.StatusCode, body)
    }
    
    var authResp struct {
        Token string `json:"token"`
    }
    
    if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
        return err
    }
    
    pc.tokenMutex.Lock()
    pc.authToken = authResp.Token
    pc.tokenMutex.Unlock()
    
    return nil
}

// StartPusher starts background goroutine to push workload labels to PSM
func (pc *PSMClient) StartPusher() {
    if !pc.enabled {
        return
    }
    
    ticker := time.NewTicker(pc.pushInterval)
    go func() {
        for range ticker.C {
            if err := pc.pushWorkloadLabels(); err != nil {
                log.Printf("PSM push error: %v", err)
                // Re-authenticate on error
                pc.authenticate()
            }
        }
    }()
}

// pushWorkloadLabels aggregates and pushes process labels to PSM
func (pc *PSMClient) pushWorkloadLabels() error {
    // Aggregate connection data into workload labels
    workloads := pc.aggregateWorkloads()
    
    if len(workloads) == 0 {
        return nil
    }
    
    data, err := json.Marshal(map[string]interface{}{
        "workloads": workloads,
        "timestamp": time.Now().Unix(),
        "hostname":  config.Hostname,
        "host_ip":   config.HostIP,
    })
    
    if err != nil {
        return err
    }
    
    req, err := http.NewRequest("POST", pc.url+"/api/v1/workloads", bytes.NewBuffer(data))
    if err != nil {
        return err
    }
    
    req.Header.Set("Content-Type", "application/json")
    pc.tokenMutex.RLock()
    req.Header.Set("Authorization", "Bearer "+pc.authToken)
    pc.tokenMutex.RUnlock()
    
    resp, err := pc.httpClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
        body, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("PSM API error: %d - %s", resp.StatusCode, body)
    }
    
    stats.Lock()
    stats.PSMSent += int64(len(workloads))
    stats.Unlock()
    
    return nil
}

// aggregateWorkloads creates workload labels from connection events
func (pc *PSMClient) aggregateWorkloads() []map[string]interface{} {
    workloads := []map[string]interface{}{}
    processMap := make(map[string]map[string]interface{})
    
    // Iterate through memory store to aggregate by process
    memoryStore.Range(func(key, value interface{}) bool {
        if evt, ok := value.(ConnectionEvent); ok {
            processKey := fmt.Sprintf("%s-%d", evt.ProcessName, evt.ProcessPID)
            
            if _, exists := processMap[processKey]; !exists {
                processMap[processKey] = map[string]interface{}{
                    "process_name": evt.ProcessName,
                    "process_pid":  evt.ProcessPID,
                    "username":     evt.Username,
                    "uid":          evt.UID,
                    "connections":  []string{},
                    "services":     map[string]bool{},
                    "labels":       map[string]string{},
                }
            }
            
            // Add connection info
            connStr := fmt.Sprintf("%s:%d", evt.DestIP, evt.DestPort)
            conns := processMap[processKey]["connections"].([]string)
            processMap[processKey]["connections"] = append(conns, connStr)
            
            // Track services
            services := processMap[processKey]["services"].(map[string]bool)
            if evt.ServiceName != "" {
                services[evt.ServiceName] = true
            }
            
            // Generate labels based on process characteristics
            labels := processMap[processKey]["labels"].(map[string]string)
            labels["app"] = evt.ProcessName
            labels["user"] = evt.Username
            labels["direction"] = evt.Direction
            
            // Add service-specific labels
            if evt.ServiceName == "mysql" || evt.ServiceName == "postgresql" {
                labels["tier"] = "database"
            } else if evt.ServiceName == "http" || evt.ServiceName == "https" {
                labels["tier"] = "web"
            } else if evt.ServiceName == "redis" {
                labels["tier"] = "cache"
            }
        }
        return true
    })
    
    // Convert map to slice
    for _, workload := range processMap {
        // Convert services map to list
        serviceList := []string{}
        if services, ok := workload["services"].(map[string]bool); ok {
            for service := range services {
                serviceList = append(serviceList, service)
            }
        }
        workload["services"] = serviceList
        
        workloads = append(workloads, workload)
    }
    
    return workloads
}

// Helper functions for managing memory store rotation
func storeInMemory(evt ConnectionEvent) {
    key := fmt.Sprintf("%d-%d", evt.ProcessPID, time.Now().UnixNano())
    memoryStore.Store(key, evt)
    
    // Cleanup old events if over limit
    go cleanupMemoryStore()
}

var cleanupMutex sync.Mutex

func cleanupMemoryStore() {
    cleanupMutex.Lock()
    defer cleanupMutex.Unlock()
    
    count := 0
    memoryStore.Range(func(key, value interface{}) bool {
        count++
        return true
    })
    
    if count <= config.Local.MaxEvents {
        return
    }
    
    // Remove oldest entries (simple FIFO for now)
    toRemove := count - config.Local.MaxEvents
    removed := 0
    
    memoryStore.Range(func(key, value interface{}) bool {
        if removed < toRemove {
            memoryStore.Delete(key)
            removed++
            return true
        }
        return false
    })
}

// Log to file with rotation support
func logToFile(evt ConnectionEvent) {
    if logFile == nil {
        return
    }
    
    data, err := json.Marshal(evt)
    if err != nil {
        return
    }
    
    logFile.Write(data)
    logFile.Write([]byte("\n"))
    
    // Check file size for rotation
    if info, err := logFile.Stat(); err == nil {
        maxSize := int64(config.Local.LogRotateSize) * 1024 * 1024
        if maxSize > 0 && info.Size() > maxSize {
            rotateLogFile()
        }
    }
}

func rotateLogFile() {
    if logFile == nil {
        return
    }
    
    logFile.Close()
    
    // Rename current file
    timestamp := time.Now().Format("20060102-150405")
    oldPath := config.Local.LogFile
    newPath := fmt.Sprintf("%s.%s", oldPath, timestamp)
    
    os.Rename(oldPath, newPath)
    
    // Open new file
    var err error
    logFile, err = os.OpenFile(oldPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
    if err != nil {
        log.Printf("Failed to rotate log file: %v", err)
    }
}