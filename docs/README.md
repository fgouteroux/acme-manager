# ACME Manager Documentation

Complete documentation for ACME Manager - an automated certificate management system with high availability clustering.

## 📖 Documentation

- **[User Documentation](user-guide.md)** - For end users managing certificates
- **[Administrator Documentation](admin-guide.md)** - For system administrators

## 🚀 Quick Links

### For Users
- [Getting Started](user-guide.md#getting-started)
- [Client Mode Setup](user-guide.md#client-mode)
- [API Reference](user-guide.md#api-reference)
- [Troubleshooting](user-guide.md#troubleshooting)

### For Administrators
- [Architecture Overview](admin-guide.md#architecture)
- [Installation Guide](admin-guide.md#installation)
- [Cluster Configuration](admin-guide.md#cluster-design)
- [Security Setup](admin-guide.md#security)
- [Monitoring & Alerts](admin-guide.md#monitoring)

## 🏗️ Architecture at a Glance

```
┌─────────────────────────────────────────────────────────────┐
│                   ACME Manager Cluster                      │
│                                                             │
│  ┌──────────┐      ┌──────────┐      ┌──────────┐           │
│  │ Instance │◄────►│ Instance │◄────►│ Instance │           │
│  │    #1    │      │    #2    │      │    #3    │           │
│  │ (Leader) │      │(Follower)│      │(Follower)│           │ 
│  └────┬─────┘      └──────────┘      └──────────┘           │ 
│       │                                                     │
│       │         Memberlist Protocol                         │
│       │                                                     │
└───────┼─────────────────────────────────────────────────────┘
        │
        ├──────► Vault (Certificate Storage)
        ├──────► ACME Servers (Let's Encrypt, Sectigo)
        └──────► Clients (Certificate Deployment)
```

## ✨ Key Features

- **Automatic Renewal**: Certificates renewed 20-30 days before expiration
- **High Availability**: Distributed cluster with automatic leader election
- **Secure Storage**: All certificates stored in HashiCorp Vault
- **Multiple Challenges**: DNS and HTTP ACME challenge support
- **Client Mode**: Automated deployment to remote servers
- **Web UI**: Certificate and token management interface
- **Monitoring**: Prometheus metrics and alerting
- **Plugin System**: Extensible architecture for custom integrations
- **Config Validation**: `--config-check` flag for both server and client
- **Forced Certificate Check**: `SIGUSR1` triggers an immediate certificate check on a running client

## 📦 Components

### Server Mode
The cluster nodes that handle certificate management:
- Certificate creation and renewal
- ACME server communication
- Vault storage integration
- API and Web UI endpoints

### Client Mode
Agents deployed on servers to fetch and deploy certificates:
- Automatic certificate retrieval
- Local file deployment
- Post-deployment command execution
- Certificate monitoring

## 🔐 Security Features

- **Token-based Authentication**: Scoped access control
- **TLS Support**: Secure API communication
- **Vault Integration**: Encrypted certificate storage
- **AppRole Authentication**: Secure Vault access
- **Audit Logging**: Complete operation tracking
- **Plugin Verification**: Checksum validation for plugins

## 📊 Monitoring

Built-in Prometheus metrics for:
- Certificate operations (create, renew, revoke)
- Cluster health and leader status
- Vault operation success/failure rates
- Token management
- ACME issuer health

## 🛠️ Technology Stack

- **Language**: Go
- **Clustering**: HashiCorp Memberlist
- **Storage**: HashiCorp Vault
- **ACME Client**: Lego library
- **Metrics**: Prometheus
- **Web Framework**: Go standard library

## 📝 Quick Start

### Server Installation

```bash
# Download and configure
./acme-manager-server \
  -config-path=config.yml \
  -ring.instance-id=node1 \
  -ring.join-members=node2:7946,node3:7946
```

### Client Installation

```bash
# Download and run
./acme-manager-client \
  -client.config-path=client-config.yml \
  -client.manager-url=https://acme-manager.example.com \
  -client.manager-token=your-token
```

## 📚 Configuration Examples

### Server Configuration

```yaml
common:
  api_key_hash: "your-sha256-hash"
  rootpath_account: /var/lib/acme-manager/accounts
  rootpath_certificate: /var/lib/acme-manager/certificates
  http_client_retry_max: 3
  http_client_retry_wait_min: 1
  http_client_retry_wait_max: 10
  plugins:
    - name: custom-dns-provider
      path: /etc/acme-manager/plugins/dns-provider.so
      checksum: "sha256:abc123..."
      timeout: 30

issuer:
  letsencrypt:
    ca_dir_url: https://acme-v02.api.letsencrypt.org/directory
    eab: false
    certificate_timeout: 300
    overall_request_limit: 20

storage:
  vault:
    url: "https://vault.example.com"
    role_id: "your-role-id"
    secret_id: "your-secret-id"
    secret_engine: "secret"
```

### Client Configuration

```yaml
common:
  certificate_deploy: true
  certificate_dir: /etc/ssl/certificates
  cmd_enabled: true
  post_cmd_run: "systemctl reload nginx"

certificate:
  - domain: "example.com"
    issuer: "letsencrypt"
    dns_challenge: "cloudflare"
    renewal_days: "30"
```

## 🔄 Certificate Lifecycle

1. **Creation**: Submit certificate request via API or config
2. **Validation**: Complete DNS or HTTP ACME challenge
3. **Storage**: Certificate stored in Vault
4. **Deployment**: Clients fetch and deploy locally
5. **Renewal**: Automatic renewal 20-30 days before expiration
6. **Cleanup**: Old versions removed after grace period

## 🌐 API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/v1/certificate` | POST | Bearer | Create certificate |
| `/api/v1/certificate` | PUT | Bearer | Update certificate |
| `/api/v1/certificate/{issuer}/{domain}` | GET | Bearer | Get certificate by issuer and domain |
| `/api/v1/certificate/{issuer}/{domain}` | DELETE | Bearer | Delete certificate by issuer and domain |
| `/api/v1/certificate/{name}` | GET | Bearer | Get named certificate |
| `/api/v1/certificate/{name}` | DELETE | Bearer | Delete named certificate |
| `/api/v1/token` | POST | API Key | Create token |
| `/metrics` | GET | None | Prometheus metrics |
| `/swagger` | GET | None | API documentation |

## 🔧 Supported Providers

### Certificate Authorities
- Let's Encrypt (Staging & Production)
- Sectigo
- Any ACME-compatible CA

### DNS Providers (100+)
- Cloudflare
- Route53 (AWS)
- Google Cloud DNS
- NS1
- OVH, GoDaddy, Gandi, and many more

## 📈 Use Cases

- **Web Servers**: Nginx, Apache, HAProxy
- **API Gateways**: Kong, Traefik, Envoy
- **Microservices**: Service-to-service TLS
- **IoT Devices**: Certificate provisioning at scale

## 🤝 Contributing

See the main repository for contribution guidelines.

## 📄 License

See the main repository for license information.

## 🔗 Resources

- [ACME Protocol (RFC 8555)](https://datatracker.ietf.org/doc/html/rfc8555)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [HashiCorp Vault](https://www.vaultproject.io/)
- [Lego ACME Client](https://go-acme.github.io/lego/)

## 📞 Support

- **Issues**: Report issues on GitHub
- **Documentation**: This documentation site
- **Community**: See main repository for community links

---

**Version**: 0.7.3+
**Last Updated**: May 2026