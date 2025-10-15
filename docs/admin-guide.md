# ACME Manager - Administrator Documentation

## Overview

This document provides comprehensive information for administrators deploying, configuring, and maintaining ACME Manager clusters.

## Table of Contents

- [Architecture](#architecture)
- [Cluster Design](#cluster-design)
- [Installation](#installation)
- [Configuration](#configuration)
- [High Availability](#high-availability)
- [API Architecture](#api-architecture)
- [Renewal Cycles](#renewal-cycles)
- [Plugin System](#plugin-system)
- [Security](#security)
- [Monitoring](#monitoring)
- [Maintenance](#maintenance)
- [Appendix](#appendix)

## Architecture

### System Overview

```mermaid
graph TB
    subgraph "ACME Manager Cluster"
        L[Leader Instance<br/>Port 8989, 7946]
        F1[Follower Instance<br/>Port 8989, 7946]
        F2[Follower Instance<br/>Port 8989, 7946]
        
        L <-->|Memberlist Gossip| F1
        F1 <-->|Memberlist Gossip| F2
        F2 <-->|Memberlist Gossip| L
    end
    
    LB[Load Balancer<br/>HTTPS]
    C1[Client 1]
    C2[Client 2]
    C3[Client N]
    
    V[(Vault<br/>Certificate Storage)]
    ACME[ACME Server<br/>Let's Encrypt/Sectigo]
    DNS[DNS Provider<br/>Cloudflare/Route53]
    
    C1 --> LB
    C2 --> LB
    C3 --> LB
    LB --> L
    LB --> F1
    LB --> F2
    
    L --> V
    L --> ACME
    L --> DNS
    
    F1 -.Proxy to Leader.-> L
    F2 -.Proxy to Leader.-> L
    
    style L fill:#4CAF50,stroke:#2E7D32,color:#fff
    style F1 fill:#2196F3,stroke:#1565C0,color:#fff
    style F2 fill:#2196F3,stroke:#1565C0,color:#fff
    style V fill:#FF9800,stroke:#E65100,color:#fff
    style ACME fill:#9C27B0,stroke:#6A1B9A,color:#fff
```

### Component Architecture

ACME Manager consists of several integrated layers:

**API Layer:**
- HTTP API endpoints (:8989/api)
- Web UI (:8989/ui)
- Prometheus metrics (:8989/metrics)
- Swagger documentation (:8989/swagger)

**Core Services:**
- Certificate Store (manages certificate lifecycle)
- Token Manager (authentication and authorization)
- Ring Manager (cluster coordination)

**Background Workers:**
- Renewal Worker (checks every 30 minutes)
- Token Expiry Worker (checks every 1 minute)
- Config Watcher (checks every 30 seconds)
- Issuer Health Checker (checks every 10 minutes)
- Cleanup Worker (optional, runs every 1 hour)

**Integration Layer:**
- Vault Client (secure storage)
- ACME Client (Lego v4.25.0)
- DNS Provider Clients
- Plugin Manager (custom providers)

```mermaid
graph TB
    subgraph "External Systems"
        ACME[ACME Server<br/>Let's Encrypt]
        DNS[DNS Provider<br/>Cloudflare]
        Vault[(Vault<br/>Storage)]
    end
    
    subgraph "ACME Manager Instance"
        API[HTTP API Layer<br/>:8989/api]
        WebUI[Web UI<br/>:8989/ui]
        Metrics[Metrics<br/>:8989/metrics]
        
        subgraph "Core Services"
            CertStore[Certificate Store]
            TokenMgr[Token Manager]
            Ring[Ring Manager]
        end
        
        subgraph "Background Workers"
            RenewWorker[Renewal Worker<br/>Every 30m]
            TokenWorker[Token Expiry Worker<br/>Every 1m]
            ConfigWorker[Config Watcher<br/>Every 30s]
            IssuerWorker[Issuer Health<br/>Every 10m]
            CleanupWorker[Cleanup Worker<br/>Every 1h]
        end
        
        subgraph "Integration Layer"
            VaultClient[Vault Client]
            ACMEClient[ACME Client - Lego v4.25.0]
            DNSClient[DNS Provider Client]
            PluginMgr[Plugin Manager]
        end
    end
    
    API --> CertStore
    API --> TokenMgr
    WebUI --> CertStore
    WebUI --> TokenMgr
    
    CertStore --> Ring
    TokenMgr --> Ring
    
    RenewWorker --> CertStore
    TokenWorker --> TokenMgr
    ConfigWorker --> CertStore
    IssuerWorker --> ACMEClient
    CleanupWorker --> VaultClient
    CleanupWorker --> ACMEClient
    
    CertStore --> VaultClient
    CertStore --> ACMEClient
    TokenMgr --> VaultClient
    
    ACMEClient --> DNSClient
    ACMEClient --> PluginMgr
    
    VaultClient --> Vault
    ACMEClient --> ACME
    DNSClient --> DNS
    PluginMgr --> DNS
    
    style API fill:#2196F3,stroke:#1565C0,color:#fff
    style CertStore fill:#4CAF50,stroke:#2E7D32,color:#fff
    style Ring fill:#9C27B0,stroke:#6A1B9A,color:#fff
    style VaultClient fill:#FF9800,stroke:#E65100,color:#fff
```

## Cluster Design

### Memberlist Protocol

ACME Manager uses HashiCorp's Memberlist for cluster coordination:

- **Gossip-based protocol**: Efficient, eventually consistent cluster state
- **Failure detection**: Automatic detection of unhealthy instances
- **Leader election**: Distributed consensus for single leader
- **KV store**: Shared key-value storage across cluster

### Leader Election

```mermaid
sequenceDiagram
    participant I1 as Instance 1
    participant I2 as Instance 2
    participant I3 as Instance 3
    participant Ring as Ring KV Store
    
    Note over I1,I3: Cluster Startup
    
    I1->>Ring: Join with Token Set
    I2->>Ring: Join with Token Set
    I3->>Ring: Join with Token Set
    
    Note over I1,I3: Leader Election
    
    I1->>Ring: Claim Token 0
    Ring-->>I1: Success - You are Leader
    
    I2->>Ring: Check Token 0 Owner
    Ring-->>I2: Token 0 owned by I1
    
    I3->>Ring: Check Token 0 Owner
    Ring-->>I3: Token 0 owned by I1
    
    Note over I1: Instance 1 is Leader
    Note over I2,I3: Instances 2,3 are Followers
    
    loop Every 5 seconds
        I1->>Ring: Heartbeat
        I2->>Ring: Heartbeat
        I3->>Ring: Heartbeat
    end
    
    Note over I1: Leader Fails
    I1--xRing: No Heartbeat
    
    Note over I2,I3: Detect Leader Failure
    
    I2->>Ring: Claim Token 0
    Ring-->>I2: Success - You are Leader
    
    Note over I2: Instance 2 is New Leader
```

**Key Characteristics:**

- Only the leader performs ACME operations
- Leader election happens automatically on startup
- If leader fails, a new leader is elected within seconds
- Token 0 is reserved for leader identification
- Followers proxy requests to the leader

### Network Communication

```mermaid
graph LR
    subgraph "External Clients"
        Users[Users/Scripts]
        Agents[ACME Clients]
        Monitoring[Prometheus]
    end
    
    subgraph "Load Balancer"
        LB[Load Balancer<br/>HTTPS 443]
    end
    
    subgraph "ACME Manager Cluster"
        Node1[Instance 1<br/>Internal IP]
        Node2[Instance 2<br/>Internal IP]
        Node3[Instance 3<br/>Internal IP]
    end
    
    subgraph "Port Usage"
        P8989[Port 8989<br/>HTTP/HTTPS API]
        P7946[Port 7946<br/>TCP/UDP Gossip]
    end
    
    Users -->|HTTPS 443| LB
    Agents -->|HTTPS 443| LB
    Monitoring -->|HTTP 443/8989| LB
    
    LB -->|HTTP 8989| Node1
    LB -->|HTTP 8989| Node2
    LB -->|HTTP 8989| Node3
    
    Node1 -.->|TCP/UDP 7946| Node2
    Node2 -.->|TCP/UDP 7946| Node3
    Node3 -.->|TCP/UDP 7946| Node1
    
    Node1 --> P8989
    Node1 --> P7946
    
    style LB fill:#2196F3,stroke:#1565C0,color:#fff
    style P8989 fill:#4CAF50,stroke:#2E7D32,color:#fff
    style P7946 fill:#FF9800,stroke:#E65100,color:#fff
```

**Port 7946 (TCP/UDP):**
- Gossip protocol communication
- State synchronization
- Failure detection
- Metadata replication
- Leader announcements

**Port 8989 (HTTP/HTTPS):**
- API endpoints
- Web UI
- Metrics endpoint
- Inter-node proxying

## Installation

### Prerequisites

- Go 1.24+ (for building from source)
- HashiCorp Vault instance
- ACME-compatible CA (Let's Encrypt, Sectigo, etc.)
- DNS provider credentials (for DNS challenges)

### Building from Source

```bash
# Clone repository
git clone https://github.com/fgouteroux/acme_manager.git
cd acme_manager

# Build server
go build -o acme-manager-server ./cmd/acme-manager-server

# Build client
go build -o acme-manager-client ./cmd/acme-manager-client
```

### Deployment

#### Single Instance (Development)

```bash
./acme-manager-server \
  -config-path=config.yml \
  -log.level=info \
  -server.listen-address=:8989
```

#### Cluster Deployment (Production)

**Instance 1 (Bootstrap):**
```bash
./acme-manager-server \
  -config-path=config.yml \
  -ring.instance-id=node1 \
  -ring.instance-addr=192.168.1.10 \
  -ring.instance-port=7946 \
  -log.level=info
```

**Instance 2:**
```bash
./acme-manager-server \
  -config-path=config.yml \
  -ring.instance-id=node2 \
  -ring.instance-addr=192.168.1.11 \
  -ring.instance-port=7946 \
  -ring.join-members=192.168.1.10:7946 \
  -log.level=info
```

**Instance 3:**
```bash
./acme-manager-server \
  -config-path=config.yml \
  -ring.instance-id=node3 \
  -ring.instance-addr=192.168.1.12 \
  -ring.instance-port=7946 \
  -ring.join-members=192.168.1.10:7946,192.168.1.11:7946 \
  -log.level=info
```

### Systemd Service

Create `/etc/systemd/system/acme-manager.service`:

```ini
[Unit]
Description=ACME Manager Server
After=network.target vault.service

[Service]
Type=simple
User=acme-manager
Group=acme-manager
WorkingDirectory=/etc/acme-manager
ExecStart=/usr/bin/acme-manager-server \
  -config-path=/etc/acme-manager/config.yml \
  -env-config-path=/etc/acme-manager/.env \
  -ring.instance-id=%H \
  -ring.join-members=node1:7946,node2:7946,node3:7946
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
systemctl daemon-reload
systemctl enable acme-manager
systemctl start acme-manager
systemctl status acme-manager
```

## Configuration

### Server Configuration

**config.yml:**
```yaml
common:
  # API key hash for token management (SHA256 hash)
  api_key_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  
  # Account and certificate storage paths
  rootpath_account: /var/lib/acme-manager/accounts
  rootpath_certificate: /var/lib/acme-manager/certificates
  
  # HTTP client retry configuration
  http_client_retry_max: 3
  http_client_retry_wait_min: 1
  http_client_retry_wait_max: 10
  http_client_retry_status_code: [429, 500, 502, 503, 504]
  
  # Plugin configuration (optional)
  plugins:
    - name: acme-manager-custom-plugin
      path: /usr/bin/acme-manager-custom-plugin
      checksum: "abc123def456..."
      timeout: 30
      env:
        MY_VAR_KEY: "your-var-key"

# ACME issuers configuration
issuer:
  # Let's Encrypt production
  letsencrypt:
    ca_dir_url: https://acme-v02.api.letsencrypt.org/directory
    eab: false
    certificate_timeout: 300
    overall_request_limit: 20
  
  # Let's Encrypt staging
  letsencrypt-staging:
    ca_dir_url: https://acme-staging-v02.api.letsencrypt.org/directory
    eab: false
    certificate_timeout: 300
  
  # Sectigo with External Account Binding
  sectigo:
    ca_dir_url: https://acme.sectigo.com/v2/OV
    eab: true
    kid: "your-kid-value"
    hmac: "your-hmac-value"
    certificate_timeout: 600
    overall_request_limit: 10

# Storage backend configuration
storage:
  vault:
    role_id: "your-vault-role-id"
    secret_id: "your-vault-secret-id"
    url: "https://vault.example.com"
    secret_engine: "secret"
    certificate_prefix: "certificates"
    token_prefix: "tokens"
    mount_path: "approle"
    retry_max: 3
    retry_wait_min: 1
    retry_wait_max: 10
```

### Environment Variables

**.env:**
```bash
# DNS provider credentials (example: Cloudflare)
CLOUDFLARE_EMAIL=admin@example.com
CLOUDFLARE_API_KEY=your-cloudflare-api-key

# DNS challenge settings
ACME_MANAGER_DNS_RESOLVERS=8.8.8.8:53,1.1.1.1:53
ACME_MANAGER_DNS_TIMEOUT=10
ACME_MANAGER_DNS_PROPAGATIONWAIT=120

# Route53 (AWS)
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_REGION=us-east-1

# Google Cloud DNS
GCE_PROJECT=your-project-id
GCE_SERVICE_ACCOUNT_FILE=/path/to/credentials.json

# Azure DNS
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
AZURE_SUBSCRIPTION_ID=your-subscription-id
AZURE_TENANT_ID=your-tenant-id
AZURE_RESOURCE_GROUP=your-resource-group
```

### Command-Line Flags

```bash
# Logging
-log.level string          # Log level: debug, info, warn, error (default "info")
-log.format string         # Log format: logfmt, json (default "logfmt")

# Server
-server.listen-address string        # Listen address (default ":8989")
-server.tls-cert-file string        # TLS certificate file
-server.tls-key-file string         # TLS key file
-server.tls-client-ca-file string   # Client CA certificate
-server.http-read-timeout int       # Read timeout in seconds (default 300)
-server.http-read-header-timeout int # Header read timeout (default 10)

# Configuration
-config-path string        # Config file path (default "config.yml")
-env-config-path string   # Environment file path (default ".env")

# Check intervals
-check-renewal-interval duration    # Certificate renewal check (default 30m)
-check-config-interval duration     # Config file check (default 30s)
-check-token-interval duration      # Token expiration check (default 1m)
-check-issuer-interval duration     # Issuer health check (default 10m)

# Cluster (Ring)
-ring.instance-id string           # Unique instance ID
-ring.instance-addr string         # Instance IP address
-ring.instance-port int            # Instance port (default 7946)
-ring.join-members string          # Comma-separated list of cluster members
-ring.heartbeat-period duration    # Heartbeat interval (default 5s)
-ring.heartbeat-timeout duration   # Heartbeat timeout (default 1m)

# Cleanup (optional)
-cleanup                                    # Enable cleanup
-cleanup.interval duration                  # Cleanup scan interval (default 1h)
-cleanup.cert-expire-days int              # Days before expiry to cleanup (default 10)
-cleanup.cert-revoke-last-version          # Revoke last version on cleanup
```

## High Availability

### Cluster Best Practices

1. **Odd Number of Nodes**: Deploy 3, 5, or 7 nodes for reliable quorum
2. **Geographic Distribution**: Spread nodes across availability zones
3. **Load Balancing**: Use a load balancer in front of API endpoints
4. **Health Checks**: Monitor `/metrics` endpoint for cluster health

### Failure Scenarios

```mermaid
stateDiagram-v2
    [*] --> Healthy: 3 Node Cluster
    
    Healthy --> LeaderFail: Leader Instance Fails
    Healthy --> FollowerFail: Follower Instance Fails
    Healthy --> NetworkPartition: Network Split
    Healthy --> VaultDown: Vault Unavailable
    
    LeaderFail --> LeaderElection: Detect Failure (30s)
    LeaderElection --> Recovering: New Leader Elected
    Recovering --> Healthy: Service Restored
    
    FollowerFail --> Degraded: 2 Nodes Active
    Degraded --> Healthy: Instance Rejoins
    
    NetworkPartition --> SplitBrain: Majority vs Minority
    SplitBrain --> Majority: Majority Continues
    SplitBrain --> Minority: Minority Read-Only
    Majority --> Reconcile: Network Healed
    Minority --> Reconcile: Network Healed
    Reconcile --> Healthy: State Synchronized
    
    VaultDown --> ReadOnly: Cache Serves Reads
    ReadOnly --> Healthy: Vault Restored
    
    note right of LeaderElection
        < 30 seconds downtime
        Automatic recovery
        No data loss
    end note
    
    note right of Degraded
        Still operational
        No leader election needed
        Reduced redundancy
    end note
    
    note right of ReadOnly
        Cannot create/update certs
        Reads work from cache
        Automatic retry
    end note
```

#### Leader Failure

**Impact:**
- Brief service interruption (< 30 seconds)
- No data loss (memberlist kv store)
- Automatic recovery

**Recovery Process:**
1. Followers detect leader failure (no heartbeat)
2. New leader election initiated
3. New leader elected within seconds
4. Service resumes normal operation

#### Network Partition

**Majority Partition:**
- Maintains quorum and continues operations
- Elects new leader if needed
- Processes all requests normally

**Minority Partition:**
- Cannot maintain quorum
- Becomes read-only
- Rejoins when partition heals

#### Vault Failure

**Impact:**
- Cannot create/read/update/delete certificates
- Read certificate metadata work from memberlist kv store
- Automatic retry with exponential backoff

**Recovery:**
- Service automatically recovers when Vault returns
- No manual intervention needed
- State remains consistent

## API Architecture

### Request Flow

```mermaid
graph TB
    Client[Client Request] --> LB[Load Balancer]
    
    LB --> I1[Instance 1]
    LB --> I2[Instance 2]
    LB --> I3[Instance 3]
    
    I1 --> Check1{Is Leader?}
    I2 --> Check2{Is Leader?}
    I3 --> Check3{Is Leader?}
    
    Check1 -->|Yes| Process1[Process Request]
    Check1 -->|No| Proxy1[Proxy to Leader]
    
    Check2 -->|Yes| Process2[Process Request]
    Check2 -->|No| Proxy2[Proxy to Leader]
    
    Check3 -->|Yes| Process3[Process Request]
    Check3 -->|No| Proxy3[Proxy to Leader]
    
    Proxy1 --> Leader[Leader Instance]
    Proxy2 --> Leader
    Proxy3 --> Leader
    
    Process1 --> Response1[Return Response]
    Process2 --> Response2[Return Response]
    Process3 --> Response3[Return Response]
    Leader --> ResponseL[Return Response]
    
    Response1 --> Client
    Response2 --> Client
    Response3 --> Client
    ResponseL --> Proxy1
    ResponseL --> Proxy2
    ResponseL --> Proxy3
    
    style Check1 fill:#FFC107,stroke:#FF6F00,color:#000
    style Check2 fill:#FFC107,stroke:#FF6F00,color:#000
    style Check3 fill:#FFC107,stroke:#FF6F00,color:#000
    style Leader fill:#4CAF50,stroke:#2E7D32,color:#fff
```

The API follows a leader-based architecture where all write operations are performed by the leader instance. Follower instances automatically proxy requests to the current leader.

**Request Processing:**
1. Client sends request to any instance (via load balancer)
2. Instance checks if it's the leader
3. If leader: Process request directly
4. If follower: Proxy to leader and return response
5. Leader performs operation (ACME, Vault, Ring KV updates)
6. Response returned to client

**Authentication Flow:**
- Admin operations: X-API-Key header (SHA256 hash verification)
- User operations: Bearer token (stored in Ring KV + Vault)
- Token scopes: read, create, update, delete

### Certificate Creation Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant API as API Server
    participant Auth as Auth Layer
    participant Store as Cert Store
    participant Lego as ACME Client
    participant ACME as ACME Server
    participant DNS as DNS Provider
    participant V as Vault
    participant KV as Ring KV
    
    C->>API: POST /api/v1/certificate
    Note over C,API: Authorization: Bearer token
    
    API->>Auth: Validate Token
    Auth->>KV: Lookup Token Hash
    KV-->>Auth: Token Data + Scope
    Auth-->>API: Authorized (scope: create)
    
    API->>Store: Create Certificate Request
    
    Store->>Lego: New ACME Order
    Lego->>ACME: POST /new-order
    ACME-->>Lego: Order with Challenges
    
    alt DNS Challenge
        Lego->>DNS: Create TXT Record
        DNS-->>Lego: Record Created
        Lego->>ACME: Ready for Validation
        ACME->>DNS: Query TXT Record
        DNS-->>ACME: TXT Record Found
    else HTTP Challenge
        Lego->>API: Serve Challenge Response
        ACME->>API: GET /.well-known/acme-challenge/
        API-->>ACME: Challenge Response
    end
    
    ACME-->>Lego: Challenge Valid
    Lego->>ACME: Finalize Order
    ACME-->>Lego: Certificate Issued
    
    Lego-->>Store: Certificate + Key
    
    Store->>V: Store Certificate
    V-->>Store: Success
    
    Store->>KV: Store Metadata
    KV-->>Store: Success
    
    Store-->>API: Certificate Created
    API-->>C: 201 Created + Certificate
```

## Renewal Cycles

### Certificate Lifecycle

```mermaid
flowchart TD
    Start([Certificate Request]) --> Create[Create Certificate]
    
    Create --> ACME[ACME Challenge]
    ACME --> DNS{Challenge Type}
    
    DNS -->|DNS-01| DNSRecord[Create DNS TXT Record]
    DNS -->|HTTP-01| HTTPServe[Serve HTTP Challenge]
    
    DNSRecord --> Validate[ACME Validation]
    HTTPServe --> Validate
    
    Validate --> Issue[Certificate Issued]
    Issue --> StoreVault[(Store in Vault)]
    StoreVault --> StoreRing[(Store Metadata in Ring)]
    StoreRing --> Active[Certificate Active]
    
    Active --> Monitor[Monitor Expiration]
    Monitor --> CheckRenewal{Within Renewal Window?}
    
    CheckRenewal -->|No| Monitor
    CheckRenewal -->|Yes| Renew[Trigger Renewal]
    
    Renew --> ACME
    
    Active --> UpdateReq{Update Requested?}
    UpdateReq -->|Yes| Revoke[Revoke Old Certificate]
    UpdateReq -->|No| Active
    
    Revoke --> Create
    
    Active --> DeleteReq{Delete Requested?}
    DeleteReq -->|Yes| RevokeDelete[Revoke Certificate]
    DeleteReq -->|No| Active
    
    RevokeDelete --> RemoveVault[(Remove from Vault)]
    RemoveVault --> RemoveRing[(Remove from Ring)]
    RemoveRing --> End([Certificate Deleted])
    
    style Create fill:#4CAF50,stroke:#2E7D32,color:#fff
    style Active fill:#2196F3,stroke:#1565C0,color:#fff
    style Renew fill:#FF9800,stroke:#E65100,color:#fff
    style Revoke fill:#F44336,stroke:#C62828,color:#fff
    style End fill:#9E9E9E,stroke:#616161,color:#fff
```

**Lifecycle Stages:**

1. **Day 0**: Certificate Created
   - Generate CSR
   - Submit to ACME server
   - Complete challenge (DNS/HTTP)
   - Receive certificate
   - Store in Vault + Ring KV

2. **Days 1-59**: Normal Operation
   - Certificate served
   - Periodic health checks
   - No action needed

3. **Days 60-70**: Renewal Window (renewal_days: "20-30")
   - Leader checks expiration every 30 minutes
   - Random day selected in range
   - Renewal process initiated
   - New certificate stored
   - Old certificate remains valid

4. **Day 71-90**: Grace Period
   - New certificate deployed
   - Old certificate still valid
   - Cleanup scheduled

5. **Day 90+**: Expiration
   - Old certificate expires
   - Cleanup removes old version (if enabled)

### Renewal Process

```mermaid
graph TB
    Start([Start]) --> CheckInterval[Every 30 Minutes]
    CheckInterval --> Leader{Is Leader?}
    
    Leader -->|No| Wait[Wait for Next Interval]
    Leader -->|Yes| ScanCerts[Scan All Certificates]
    
    ScanCerts --> CheckExpiry{Check Each Cert<br/>Expiration Date}
    
    CheckExpiry -->|Not in Renewal Window| NextCert[Next Certificate]
    CheckExpiry -->|In Renewal Window| ParseRenewal[Parse renewal_days]
    
    ParseRenewal --> CalcDate[Calculate Random Date<br/>in Range]
    CalcDate --> CheckDate{Is Today the<br/>Renewal Date?}
    
    CheckDate -->|No| NextCert
    CheckDate -->|Yes| StartRenewal[Start Renewal Process]
    
    StartRenewal --> GenCSR[Generate New CSR]
    GenCSR --> RequestCert[Request from ACME]
    RequestCert --> Challenge[Complete Challenge]
    Challenge --> GetCert[Retrieve Certificate]
    GetCert --> StoreVault[Store in Vault]
    StoreVault --> UpdateKV[Update Ring KV]
    UpdateKV --> Metrics[Update Metrics]
    Metrics --> NotifyClients[Clients Auto-Detect Update]
    
    NotifyClients --> NextCert
    NextCert --> MoreCerts{More<br/>Certificates?}
    
    MoreCerts -->|Yes| CheckExpiry
    MoreCerts -->|No| Wait
    
    Wait --> CheckInterval
    
    style Start fill:#4CAF50,stroke:#2E7D32,color:#fff
    style Leader fill:#2196F3,stroke:#1565C0,color:#fff
    style StartRenewal fill:#FF9800,stroke:#E65100,color:#fff
    style StoreVault fill:#9C27B0,stroke:#6A1B9A,color:#fff
```

### Background Workers

**Leader Only:**
- Certificate Renewal Checker (every 30m)
- Cleanup Worker (every 1h, optional)

**All Instances:**
- Token Expiration Checker (every 1m)
- Config File Watcher (every 30s)
- Issuer Health Checker (every 10m)
- Ring KV Store Watcher (continuous)

## Plugin System

### Overview

ACME Manager supports a plugin system for extending DNS provider support beyond the built-in Lego providers.

### Plugin Architecture

```mermaid
graph TB
    subgraph "ACME Manager"
        ACMEClient[ACME Client - Lego]
        PluginMgr[Plugin Manager]
        ConfigLoader[Config Loader]
    end
    
    subgraph "Built-in DNS Providers"
        Cloudflare[Cloudflare Provider]
        Route53[Route53 Provider]
        GCP[GCP DNS Provider]
        Azure[Azure DNS Provider]
    end
    
    subgraph "Custom Plugins"
        Plugin1[Custom DNS Plugin 1<br/>.so file]
        Plugin2[Custom DNS Plugin 2<br/>.so file]
    end
    
    subgraph "Plugin Security"
        Checksum[SHA256 Checksum<br/>Verification]
        Timeout[Timeout Protection]
        EnvIsolation[Environment Isolation]
    end
    
    ConfigLoader --> PluginMgr
    PluginMgr --> Checksum
    PluginMgr --> Timeout
    PluginMgr --> EnvIsolation
    
    ACMEClient --> PluginMgr
    ACMEClient --> Cloudflare
    ACMEClient --> Route53
    ACMEClient --> GCP
    ACMEClient --> Azure
    
    PluginMgr --> Plugin1
    PluginMgr --> Plugin2
    
    Plugin1 --> DNS[DNS Provider API]
    Plugin2 --> DNS
    
    style PluginMgr fill:#4CAF50,stroke:#2E7D32,color:#fff
    style Checksum fill:#F44336,stroke:#C62828,color:#fff
    style Plugin1 fill:#FF9800,stroke:#E65100,color:#fff
    style Plugin2 fill:#FF9800,stroke:#E65100,color:#fff
```

### Plugin Configuration

```yaml
common:
  plugins:
    - name: acme-manager-custom-plugin
      path: /usr/bin/acme-manager-custom-plugin
      checksum: "abc123def456789..."
      timeout: 30
      env:
        MY_VAR_KEY: "your-var-key"
```

### Plugin Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | Yes | Unique plugin identifier |
| `path` | string | Yes | Absolute path to plugin .so file |
| `checksum` | string | Yes | SHA256 checksum for verification |
| `timeout` | int | No | Execution timeout in seconds (default: 30) |
| `env` | map | No | Environment variables for the plugin |


### Building Plugins

```bash
# Build plugin
go build -o acme-manager-custom-plugin main.go

# Calculate checksum
sha256sum acme-manager-custom-plugin
# Output: abc123def456789... acme-manager-custom-plugin
```

### Plugin Security

**Security Measures:**

1. **Checksum Verification**: SHA256 checksums prevent tampering
2. **Isolated Execution**: Plugins run with controlled access
3. **Timeout Protection**: Configurable timeouts prevent hangs
4. **Environment Isolation**: Plugin-specific environment variables

## Security

### Vault Integration

```mermaid
graph TB
    subgraph instances["🔧 ACME Manager Instances"]
        I1[Instance 1]
        I2[Instance 2]
        I3[Instance 3]
    end
    
    subgraph auth["🔐 Vault Authentication"]
        AppRole[AppRole Auth Method]
        RoleID[Role ID]
        SecretID[Secret ID]
    end
    
    subgraph vault["🗄️ Vault Storage"]
        KV[KV Secrets Engine v2]
        
        subgraph certs["📜 Certificates Path"]
            CertPath[/secret/certificates/user/]
            LE[Let's Encrypt]
            SEC[Sectigo]
            Domain1[example.com<br/>versions: v1, v2, v3]
            Domain2[api.example.com<br/>versions: v1, v2]
        end
        
        subgraph tokens["🎫 Tokens Path"]
            TokenPath[/secret/tokens/]
            Token1[UUID-1]
            Token2[UUID-2]
            Token3[UUID-N]
        end
    end
    
    I1 -.-> AppRole
    I2 -.-> AppRole
    I3 -.-> AppRole
    
    AppRole --> RoleID
    AppRole --> SecretID
    
    RoleID --> VToken[✅ Vault Token + TTL]
    SecretID --> VToken
    
    VToken ==> KV
    
    KV --> CertPath
    KV --> TokenPath
    
    CertPath --> LE
    CertPath --> SEC
    
    LE --> Domain1
    LE --> Domain2
    
    TokenPath --> Token1
    TokenPath --> Token2
    TokenPath --> Token3
    
    classDef instanceStyle fill:#2196F3,stroke:#1565C0,stroke-width:2px,color:#fff
    classDef authStyle fill:#9C27B0,stroke:#6A1B9A,stroke-width:2px,color:#fff
    classDef tokenStyle fill:#4CAF50,stroke:#2E7D32,stroke-width:3px,color:#fff
    classDef kvStyle fill:#FF9800,stroke:#E65100,stroke-width:3px,color:#fff
    classDef certStyle fill:#00BCD4,stroke:#00838F,stroke-width:2px,color:#fff
    classDef tokenPathStyle fill:#FFC107,stroke:#F57C00,stroke-width:2px,color:#000
    classDef domainStyle fill:#E1F5FE,stroke:#0277BD,stroke-width:2px,color:#000
    classDef uuidStyle fill:#FFF9C4,stroke:#F9A825,stroke-width:2px,color:#000
    
    class I1,I2,I3 instanceStyle
    class AppRole,RoleID,SecretID authStyle
    class VToken tokenStyle
    class KV kvStyle
    class CertPath,LE,SEC certStyle
    class TokenPath tokenPathStyle
    class Domain1,Domain2 domainStyle
    class Token1,Token2,Token3 uuidStyle
```

**AppRole Authentication:**

The system uses HashiCorp Vault's AppRole authentication method for secure access to secrets.

**Authentication Process:**
1. ACME Manager starts with RoleID and SecretID
2. Authenticates to Vault using AppRole
3. Receives time-limited token (typically 1 hour TTL)
4. Token cached and automatically renewed before expiration
5. All Vault operations use the current valid token

### Token Authentication

```mermaid
graph TB
    subgraph "Token Creation (Admin Only)"
        Admin[Admin] --> CreateReq[POST /api/v1/token]
        CreateReq --> AdminKey{X-API-Key Valid?}
        AdminKey -->|No| Reject1[401 Unauthorized]
        AdminKey -->|Yes| GenToken[Generate UUID + Token]
        GenToken --> HashToken[SHA256 Hash Token]
        HashToken --> StoreV[Store in Vault]
        StoreV --> StoreKV[Store in Ring KV]
        StoreKV --> ReturnToken[Return Bearer Token Once]
    end
    
    subgraph "Token Usage (Users)"
        User[User] --> UseReq[Request with Bearer Token]
        UseReq --> ExtractToken[Extract Token from Header]
        ExtractToken --> HashCheck[Calculate SHA256 Hash]
        HashCheck --> LookupKV[Lookup in Ring KV]
        LookupKV --> Expired{Token Expired?}
        Expired -->|Yes| Reject2[401 Unauthorized]
        Expired -->|No| CheckScope{Has Required Scope?}
        CheckScope -->|No| Reject3[403 Forbidden]
        CheckScope -->|Yes| Authorized[Process Request]
    end
    
    ReturnToken -.Token Shared with User.-> User
    
    style GenToken fill:#4CAF50,stroke:#2E7D32,color:#fff
    style Authorized fill:#4CAF50,stroke:#2E7D32,color:#fff
    style Reject1 fill:#F44336,stroke:#C62828,color:#fff
    style Reject2 fill:#F44336,stroke:#C62828,color:#fff
    style Reject3 fill:#F44336,stroke:#C62828,color:#fff
```

### API Security

**Token Scopes:**

| Scope | Permissions |
|-------|------------|
| `read` | GET certificates, GET token info |
| `create` | POST certificates |
| `update` | PUT certificates |
| `delete` | DELETE certificates, REVOKE certificates |

**Security Best Practices:**

1. **Token Management:**
   - Use minimal required scopes
   - Set appropriate expiration times (30-90 days)
   - Rotate tokens regularly
   - Use SHA256 hashing
   - Store tokens securely

2. **TLS Configuration:**
   ```bash
   # Generate cert for production
   openssl req -x509 -newkey rsa:4096 -nodes \
     -keyout server.key -out server.crt \
     -days 365 -subj "/CN=acme-manager.example.com"
   
   # Run with TLS
   ./acme-manager-server \
     -server.tls-cert-file=server.crt \
     -server.tls-key-file=server.key \
     -server.tls-client-ca-file=ca.crt
   ```

3. **Vault Security:**
   - Use dedicated AppRole for ACME Manager
   - Apply least-privilege policies
   - Enable audit logging
   - Rotate SecretID regularly

**Example Vault Policy:**
```hcl
path "secret/data/certificates/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/data/tokens/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
```

## Monitoring

### Prometheus Metrics

**Application Metrics:**

```prometheus
# Certificate operations
acme_manager_certificate_total
acme_manager_certificate_created
acme_manager_certificate_revoke
acme_manager_certificate_renewed

# Local Certificate operations
acme_manager_local_certificate_created_total
acme_manager_local_certificate_deleted_total

# Local command pre/post run
acme_manager_local_cmd_run_success_total
acme_manager_local_cmd_run_failed_total

# Vault operations
acme_manager_vault_get_secret_success_total
acme_manager_vault_put_secret_success_total
acme_manager_vault_delete_secret_success_total
acme_manager_vault_get_secret_failed_total
acme_manager_vault_put_secret_failed_total
acme_manager_vault_delete_secret_failed_total

# Config file
acme_manager_config_reload
acme_manager_config_error

# Issuer health
acme_manager_issuer_config_error{issuer}

# System metrics
acme_manager_build_info{version, revision, branch, goversion}
```

**Ring/Cluster Metrics:**

```prometheus
# Memberlist
acme_manager_memberlist_client_cas_attempt_total
acme_manager_memberlist_client_cas_failure_total
acme_manager_memberlist_client_cas_success_total
acme_manager_memberlist_client_cluster_members_count
acme_manager_memberlist_client_cluster_node_health_score
acme_manager_memberlist_client_kv_store_count
acme_manager_memberlist_client_kv_store_value_tombstones
acme_manager_memberlist_client_kv_store_value_tombstones_removed_total
acme_manager_memberlist_client_messages_in_broadcast_queue
acme_manager_memberlist_client_messages_in_broadcast_queue_bytes
acme_manager_memberlist_client_messages_to_broadcast_dropped_total
acme_manager_memberlist_client_pending_key_notifications
acme_manager_memberlist_client_received_broadcasts_bytes_total
acme_manager_memberlist_client_received_broadcasts_dropped_total
acme_manager_memberlist_client_received_broadcasts_invalid_total
acme_manager_memberlist_client_received_broadcasts_total
acme_manager_memberlist_client_state_pulls_bytes_total
acme_manager_memberlist_client_state_pulls_total
acme_manager_memberlist_client_state_pushes_bytes_total

# Ring operations
acme_manager_ring_member_heartbeats_total
acme_manager_ring_member_tokens_owned
acme_manager_ring_member_tokens_to_own
acme_manager_ring_members
acme_manager_ring_oldest_member_timestamp
acme_manager_ring_tokens_total
```

### Grafana Dashboard

**Example PromQL Queries:**

```promql
# Certificate creation rate
rate(acme_manager_certificate_created[5m])

# Certificates by issuer
sum by (issuer) (acme_manager_certificate_total)

# Cluster members
count(up{job="acme-manager"})

# Get Leader node
acme_manager_node_role == 1

# Get Follower nodes
acme_manager_node_role == 2

# Certificate expiration alerts
acme_manager_certificate_expiry < 30
```

### Alerting Rules

{% raw %}
```yaml
groups:
  - name: acme_manager
    interval: 30s
    rules:
      # Certificate expiring soon
      - alert: CertificateExpiringSoon
        expr: acme_manager_certificate_expiry < 7
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Certificate {{ $labels.domain }} expires in < 7 days"
          description: "Certificate for {{ $labels.domain }} from {{ $labels.issuer }} will expire in less than 7 days"
      
      # No cluster leader
      - alert: NoClusterLeader
        expr: count(acme_manager_node_role == 1) == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "ACME Manager cluster has no leader"
          description: "The ACME Manager cluster has no active leader. Certificate operations are blocked."
      
      # Issuer health check failing
      - alert: IssuerUnhealthy
        expr: acme_manager_issuer_config_error > 0
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Issuer {{ $labels.issuer }} health check failing"
          description: "The ACME issuer {{ $labels.issuer }} has been unhealthy for 10 minutes"
      
      # Instance down
      - alert: ACMEManagerDown
        expr: up{job="acme-manager"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "ACME Manager instance {{ $labels.instance }} is down"
          description: "Instance {{ $labels.instance }} has been down for 5 minutes"
```
{% endraw %}

## Maintenance

### Backup Procedures

```bash
#!/bin/bash
# Backup all certificates
BACKUP_DIR="backup/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR/certificates"

vault kv list -format=json secret/certificates/ | \
  jq -r '.[]' | \
  while read path; do
    vault kv get -format=json "secret/certificates/$path" > \
      "$BACKUP_DIR/certificates/${path//\//_}.json"
  done
```

### Deployment Topology

```mermaid
graph TB
    subgraph "Production Environment"
        subgraph "Availability Zone 1"
            N1[ACME Manager<br/>Instance 1<br/>Leader]
            C1[Client 1]
            C2[Client 2]
        end
        
        subgraph "Availability Zone 2"
            N2[ACME Manager<br/>Instance 2<br/>Follower]
            C3[Client 3]
            C4[Client 4]
        end
        
        subgraph "Availability Zone 3"
            N3[ACME Manager<br/>Instance 3<br/>Follower]
            C5[Client 5]
            C6[Client 6]
        end
    end
    
    subgraph "Shared Services"
        LB[Load Balancer]
        Vault[(Vault Cluster)]
        Monitoring[Prometheus + Grafana]
    end
    
    subgraph "External Services"
        ACME[Let's Encrypt]
        DNS[DNS Provider]
    end
    
    N1 <--> N2
    N2 <--> N3
    N3 <--> N1
    
    C1 --> LB
    C2 --> LB
    C3 --> LB
    C4 --> LB
    C5 --> LB
    C6 --> LB
    
    LB --> N1
    LB --> N2
    LB --> N3
    
    N1 --> Vault
    N2 --> Vault
    N3 --> Vault
    
    N1 --> ACME
    N1 --> DNS
    
    N1 --> Monitoring
    N2 --> Monitoring
    N3 --> Monitoring
    
    style N1 fill:#4CAF50,stroke:#2E7D32,color:#fff
    style N2 fill:#2196F3,stroke:#1565C0,color:#fff
    style N3 fill:#2196F3,stroke:#1565C0,color:#fff
    style LB fill:#FF9800,stroke:#E65100,color:#fff
    style Vault fill:#9C27B0,stroke:#6A1B9A,color:#fff
```

## Appendix

### Supported DNS Providers (100+)

- Cloudflare, Route53, Google Cloud DNS, Azure DNS
- OVH, GoDaddy, Gandi, DigitalOcean, Linode
- And many more via Lego library

### API Endpoint Summary

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/v1/certificate/{issuer}/{domain}` | Bearer | Get certificate |
| POST | `/api/v1/certificate` | Bearer | Create certificate |
| PUT | `/api/v1/certificate` | Bearer | Update certificate |
| DELETE | `/api/v1/certificate/{issuer}/{domain}` | Bearer | Delete certificate |
| GET | `/metrics` | None | Prometheus metrics |
| GET | `/swagger` | None | API documentation |

---

**Version:** 0.6.1+  
**Last Updated:** October 2025  
**Go Version:** 1.24+