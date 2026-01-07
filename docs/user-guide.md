# ACME Manager - User Documentation

## Overview

ACME Manager is a distributed system designed to automate the creation, management, and deployment of ACME (Automated Certificate Management Environment) certificates. It provides a robust solution for managing TLS/SSL certificates across your infrastructure with automatic renewal and secure storage.

## Table of Contents

- [Key Features](#key-features)
- [Getting Started](#getting-started)
- [Client Mode](#client-mode)
- [API Reference](#api-reference)
- [Authentication](#authentication)
- [Certificate Management](#certificate-management)
- [Monitoring](#monitoring)

## Key Features

- **Automatic Certificate Renewal**: Certificates are automatically renewed 20-30 days before expiration
- **High Availability**: Operates in a distributed cluster with automatic leader election
- **Secure Storage**: All certificates are securely stored in HashiCorp Vault
- **Multiple Challenge Types**: Supports both DNS and HTTP ACME challenges
- **Web UI**: User-friendly interface for certificate and token management
- **Client Mode**: Deploy certificates locally on remote servers
- **Command Execution**: Run custom commands after certificate deployment
- **Real-time Monitoring**: Prometheus metrics and web dashboard
- **Plugin Support**: Extensible DNS provider plugins

## Getting Started

### Prerequisites

- Access to an ACME Manager server URL
- An authentication token (provided by your administrator)
- For client mode: ACME Manager client binary

### Authentication

ACME Manager uses two types of authentication:

#### 1. API Key Authentication (Admin Only)

Used for token management operations:

```bash
curl -X GET 'http://localhost:8989/api/v1/token/{id}' \
  -H 'X-API-Key: your-api-key'
```

#### 2. Bearer Token Authentication (Users)

Used for certificate operations:

```bash
curl -X GET 'http://localhost:8989/api/v1/certificate/{issuer}/{domain}' \
  -H 'Authorization: Bearer your-token-here'
```

## Client Mode

The ACME Manager client runs on your servers to automatically fetch and deploy certificates from the ACME Manager cluster.

### Installation

1. Download the `acme-manager-client` binary
2. Create a configuration file
3. Run the client

### Client Configuration

Create a `client-config.yml` file:

```yaml
common:
  # Default certificate settings
  cert_days: 90                       # Default validity period
  cert_days_renewal: "20-30"          # Default renewal window

  # Certificate deployment
  certificate_deploy: true
  certificate_backup: false           # Backup certs/keys to Vault
  certificate_dir: /etc/ssl/certificates
  certificate_dir_perm: 0700
  certificate_file_perm: 0600
  certificate_keyfile_perm: 0600
  certificate_file_ext: ".crt"
  certificate_keyfile_ext: ".key"
  certificate_ca_file_ext: ".ca.crt"  # Used when bundle=false
  certificate_keyfile_no_generate: false  # Use existing local key
  certificate_timeout: 180            # Timeout for cert operations

  # Command execution
  cmd_enabled: true
  pre_cmd_run: ""                     # Command before deployment
  pre_cmd_timeout: 60
  post_cmd_run: "systemctl reload nginx"
  post_cmd_timeout: 60

  # Certificate lifecycle
  revoke_on_update: false
  revoke_on_delete: false
  delay_before_delete: ""             # e.g., "24h"

certificate:
  - domain: "example.com"
    issuer: "letsencrypt"
    dns_challenge: "cloudflare"
    san: "www.example.com,api.example.com"
    days: 90                          # Override default validity
    renewal_days: "30"                # Override default renewal window
    bundle: true
    key_type: "ec256"
    labels: "env=prod,team=infra"
    profile: ""                       # ACME profile (if CA supports it)

storage:
  vault:
    url: "https://vault.example.com"
    role_id: "your-role-id"
    secret_id: "your-secret-id"
    cert_prefix: "secret/acme-manager/certificates"  # For certificate_backup
```

### Running the Client

```bash
acme-manager-client \
  -client.config-path=client-config.yml \
  -client.manager-url=https://acme-manager.example.com \
  -client.manager-token=your-bearer-token \
  -client.check-config-interval=5m
```

### Client CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `-client.config-path` | `client-config.yml` | Path to the client configuration file |
| `-client.manager-url` | `http://localhost:8989/api/v1` | ACME Manager server URL (or env var `ACME_MANAGER_URL`) |
| `-client.manager-token` | "" | Bearer token for authentication (or env var `ACME_MANAGER_TOKEN`) |
| `-client.check-config-interval` | `5m` | Interval to check for config changes and sync certificates |
| `-client.pull-only` | `false` | Enable pull-only (slave) mode |
| `-client.cleanup-enabled` | `false` | Enable cleanup of orphaned local certificate files |
| `-client.cleanup-interval` | `30m` | Interval to check for orphaned files to cleanup |
| `-client.tls-ca-file` | "" | TLS CA certificate file for server connection |
| `-client.tls-cert-file` | "" | TLS client certificate file |
| `-client.tls-key-file` | "" | TLS client key file |
| `-client.tls-skip-verify` | `false` | Skip TLS certificate verification |
| `-server.listen-address` | `:8989` | Address for the metrics HTTP server |
| `-log.level` | `info` | Log level (debug, info, warn, error) |
| `-log.format` | `logfmt` | Log format (logfmt, json) |

### Master/Slave Mode

ACME Manager client supports two operational modes that enable a master/slave architecture for certificate management:

#### Master Mode (Default)

In master mode, the client is responsible for:
- Managing the full certificate lifecycle (create, update, delete)
- Generating CSRs and private keys
- Syncing certificates from the local config file to the ACME Manager server
- Deploying certificates locally

```bash
acme-manager-client \
  -client.config-path=client-config.yml \
  -client.manager-url=https://acme-manager.example.com \
  -client.manager-token=your-bearer-token
```

#### Slave Mode (Pull-Only)

In slave mode (`-client.pull-only=true`), the client only:
- Lists certificates from the KV ring (server storage)
- Pulls and deploys certificates locally
- Restores private keys from Vault backup (requires `certificate_backup` enabled on master)
- Does NOT create, update, or delete certificates on the server

This mode is useful for:
- Deploying certificates to multiple servers without managing them
- Separating certificate management from deployment
- High-availability setups where one master manages certificates and multiple slaves deploy them

```bash
acme-manager-client \
  -client.pull-only=true \
  -client.config-path=client-config.yml \
  -client.manager-url=https://acme-manager.example.com \
  -client.manager-token=your-bearer-token
```

**Note:** In pull-only mode, the `certificate` section in the config file is not required. The client will fetch all certificates available to the token from the server.

#### Master/Slave Architecture Example

```
┌─────────────────────────────────────────────────────────────┐
│                    ACME Manager Server                       │
│                    (Certificate Store)                       │
└─────────────────────────────────────────────────────────────┘
                            ▲
           ┌────────────────┼────────────────┐
           │                │                │
    ┌──────┴──────┐  ┌──────┴──────┐  ┌──────┴──────┐
    │   Master    │  │   Slave 1   │  │   Slave 2   │
    │   Client    │  │   Client    │  │   Client    │
    │             │  │ (pull-only) │  │ (pull-only) │
    │ - Manages   │  │             │  │             │
    │   certs     │  │ - Deploys   │  │ - Deploys   │
    │ - Creates   │  │   only      │  │   only      │
    │ - Updates   │  │             │  │             │
    │ - Deletes   │  │             │  │             │
    └─────────────┘  └─────────────┘  └─────────────┘
           │                │                │
           ▼                ▼                ▼
    ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
    │  App Server │  │  App Server │  │  App Server │
    │     #1      │  │     #2      │  │     #3      │
    └─────────────┘  └─────────────┘  └─────────────┘
```

**Configuration for Slave Mode:**

```yaml
common:
  certificate_deploy: true
  certificate_dir: /etc/ssl/certificates
  certificate_file_ext: ".crt"
  certificate_keyfile_ext: ".key"
  cmd_enabled: true
  post_cmd_run: "systemctl reload nginx"

# certificate section is optional in pull-only mode
# The client will pull all certificates available to the token

storage:
  vault:
    url: "https://vault.example.com"
    role_id: "your-role-id"
    secret_id: "your-secret-id"
    cert_prefix: "secret/acme-manager/certificates"
```

### Client Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                    ACME Manager Client                       │
└─────────────────────────────────────────────────────────────┘
                            │
                            │ 1. Read config file
                            ▼
                    ┌───────────────┐
                    │ Configuration │
                    └───────────────┘
                            │
                            │ 2. Fetch certificates
                            ▼
                ┌───────────────────────┐
                │   ACME Manager API    │
                └───────────────────────┘
                            │
                            │ 3. Deploy locally
                            ▼
                    ┌───────────────┐
                    │ /etc/ssl/...  │
                    └───────────────┘
                            │
                            │ 4. Run post command
                            ▼
                    ┌───────────────┐
                    │ systemctl...  │
                    └───────────────┘
                            │
                            │ 5. Check for updates (every 5m)
                            ▼
                        [Repeat]
```

## API Reference

### Certificate Operations

#### Get Certificate

Retrieve a specific certificate:

```bash
GET /api/v1/certificate/{issuer}/{domain}
Authorization: Bearer {token}
```

Response:
```json
{
  "cert": "-----BEGIN CERTIFICATE-----\n...",
  "ca_issuer": "-----BEGIN CERTIFICATE-----\n...",
  "issuer": "letsencrypt",
  "domain": "example.com",
  "owner": "username",
  "expires": "2025-10-14 12:00:00",
  "renewal_date": "2025-09-14 12:00:00"
}
```

#### Create Certificate

Create a new certificate:

```bash
POST /api/v1/certificate
Authorization: Bearer {token}
Content-Type: application/json

{
  "domain": "example.com",
  "issuer": "letsencrypt",
  "dns_challenge": "cloudflare",
  "san": "www.example.com,api.example.com",
  "renewal_days": "30",
  "bundle": true,
  "key_type": "RSA2048"
}
```

#### Update Certificate

Update an existing certificate (revokes the old one):

```bash
PUT /api/v1/certificate
Authorization: Bearer {token}
Content-Type: application/json

{
  "domain": "example.com",
  "issuer": "letsencrypt",
  "dns_challenge": "cloudflare",
  "san": "www.example.com,api.example.com,new.example.com",
  "renewal_days": "30",
  "revoke": true
}
```

#### Delete Certificate

Delete and optionally revoke a certificate:

```bash
DELETE /api/v1/certificate/{issuer}/{domain}
Authorization: Bearer {token}
```

#### Get Certificate Metadata

Get certificate metadata without the actual certificate data:

```bash
GET /api/v1/certificate/metadata?issuer={issuer}&domain={domain}
Authorization: Bearer {token}
```

Response:
```json
{
  "domain": "example.com",
  "issuer": "letsencrypt",
  "san": ["www.example.com", "api.example.com"],
  "expires": "2025-10-14 12:00:00",
  "fingerprint": "SHA256:...",
  "serial": "03:04:05:06:07:08",
  "issuer_cn": "Let's Encrypt Authority X3"
}
```

### Token Operations

#### Get Token Information

View your current token details:

```bash
GET /api/v1/token/self
Authorization: Bearer {token}
```

Response:
```json
{
  "tokenHash": "sha256-hash",
  "username": "your-username",
  "expires": "2025-11-14 12:00:00",
  "duration": "30d",
  "scope": ["read", "create", "update", "delete"]
}
```

## Certificate Management

### Certificate Renewal

Certificates are automatically renewed based on the `renewal_days` parameter:

- **Single value** (e.g., `"30"`): Renewal occurs exactly 30 days before expiration
- **Range** (e.g., `"20-30"`): Renewal occurs randomly between 20-30 days before expiration

**Short-lived Certificates**: For certificates with a lifetime shorter than the renewal window (e.g., 6-day certificate with `renewal_days: "20-30"`), the system automatically switches to percentage-based renewal, renewing at 50-75% of the certificate's lifetime.

### Certificate Bundling

When `bundle: true` is set, the certificate includes the full chain:

```
-----BEGIN CERTIFICATE-----
[Your Certificate]
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
[Intermediate Certificate]
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
[Root Certificate]
-----END CERTIFICATE-----
```

When `bundle: false`, the CA chain is saved as a separate file:
- Certificate: `domain.crt`
- Private key: `domain.key`
- CA chain: `domain.ca.crt` (configurable via `certificate_ca_file_ext`)

### ACME Profiles

Some Certificate Authorities support custom certificate profiles via the ACME protocol (draft-aaron-acme-profiles). This allows requesting certificates with specific Key Usage or Extended Key Usage extensions.

```yaml
certificate:
  - domain: "example.com"
    issuer: "letsencrypt"
    profile: "shortlived" # CA-specific profile name
```

**Note**: Profile support depends on the CA. Contact your CA to confirm support and available profile names.

### Challenge Types

#### DNS Challenge

Requires DNS provider credentials configured on the server:

```yaml
dns_challenge: "cloudflare"  # or route53, gcp, azure, etc.
```

#### HTTP Challenge

Requires HTTP accessibility on port 80:

```yaml
http_challenge: "kvring"
```

## Monitoring

### Web UI

Access the web interface at:

- **Certificates**: `http://acme-manager.example.com:8989/certificates`
- **Tokens**: `http://acme-manager.example.com:8989/tokens`
- **Swagger API**: `http://acme-manager.example.com:8989/swagger`

### Metrics

Client metrics are exposed at:

```
http://localhost:8989/metrics
```

## Common Configuration Options

### Certificate Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `domain` | string | required | Primary domain name |
| `issuer` | string | required | Certificate authority (e.g., "letsencrypt") |
| `san` | string | "" | Subject Alternative Names (comma-separated) |
| `dns_challenge` | string | "" | DNS provider for DNS-01 challenge |
| `http_challenge` | string | "" | HTTP-01 challenge method |
| `days` | int | 90 | Certificate validity period in days (if CA supports it) |
| `renewal_days` | string | "20-30" | Days before expiration to renew |
| `bundle` | bool | false | Include CA chain in certificate. When false, CA chain saved as separate file |
| `key_type` | string | "ec256" | Private key type (RSA2048, RSA4096, EC256, EC384) |
| `labels` | string | "" | Custom labels for the certificate (key=value,key2=value2) |
| `profile` | string | "" | ACME profile for custom certificate issuance (requires CA support) |

### Client Deployment Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `cert_days` | int | 90 | Default certificate validity period in days |
| `cert_days_renewal` | string | "20-30" | Default renewal window (days before expiration) |
| `certificate_deploy` | bool | false | Deploy certificates locally |
| `certificate_backup` | bool | false | Backup certificates and private keys to Vault |
| `certificate_dir` | string | "" | Directory for certificate deployment |
| `certificate_dir_perm` | octal | 0700 | Directory permissions |
| `certificate_file_perm` | octal | 0600 | Certificate file permissions |
| `certificate_keyfile_perm` | octal | 0600 | Private key file permissions |
| `certificate_file_ext` | string | ".crt" | Certificate file extension |
| `certificate_keyfile_ext` | string | ".key" | Private key file extension |
| `certificate_ca_file_ext` | string | ".ca.crt" | CA chain file extension (used when bundle=false) |
| `certificate_keyfile_no_generate` | bool | false | Do not generate private key, use existing local key file |
| `certificate_timeout` | int | 180 | Timeout in seconds for certificate operations |
| `cmd_enabled` | bool | false | Enable command execution |
| `pre_cmd_run` | string | "" | Command to run before deployment |
| `pre_cmd_timeout` | int | 60 | Pre-command timeout in seconds |
| `post_cmd_run` | string | "" | Command to run after deployment |
| `post_cmd_timeout` | int | 60 | Post-command timeout in seconds |
| `revoke_on_update` | bool | false | Revoke old certificate on update |
| `revoke_on_delete` | bool | false | Revoke certificate on delete |
| `delay_before_delete` | string | "" | Duration to wait before deleting (e.g., "24h") |

## Best Practices

### Security

1. **Protect your tokens**: Store tokens securely and never commit them to version control
2. **Use minimal scopes**: Request only the permissions you need
3. **Rotate tokens regularly**: Set appropriate expiration times
4. **Secure certificate directories**: Use restrictive file permissions (0600 for keys)

### Certificate Management

1. **Use certificate bundling**: Enable `bundle: true` for compatibility
2. **Set appropriate renewal windows**: Use ranges like "20-30" to distribute load
3. **Monitor expiration**: Set up alerts for certificates nearing expiration
4. **Test in staging**: Use Let's Encrypt staging environment for testing

### Client Deployment

1. **Run as a service**: Use systemd or similar to ensure the client runs continuously
2. **Monitor logs**: Regularly check client logs for errors
3. **Test commands**: Verify post-deployment commands work correctly
4. **Use configuration management**: Deploy client configs via Ansible/Puppet/Chef

## Troubleshooting

### Certificate Not Deploying

1. Check client logs for errors
2. Verify token has correct permissions
3. Ensure certificate exists on server
4. Check file system permissions

### Command Execution Fails

1. Verify command path and syntax
2. Check command timeout value
3. Ensure user has permission to run command
4. Test command manually first

### API Authentication Errors

1. Verify token is not expired
2. Check token scope includes required permission
3. Ensure correct Authorization header format
4. Contact administrator if token is invalid

## Support

For issues and questions:

- Check server logs: `journalctl -u acme-manager`
- Review Prometheus metrics
- Contact your system administrator
- Review the administrator documentation

## Additional Resources

- [ACME RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)

---

**Version**: 0.6.9+
**Last Updated**: January 2026