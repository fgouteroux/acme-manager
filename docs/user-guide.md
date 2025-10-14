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
  certificate_deploy: true
  certificate_dir: /etc/ssl/certificates
  certificate_dir_perm: 0700
  certificate_file_perm: 0600
  certificate_keyfile_perm: 0600
  certificate_file_ext: ".crt"
  certificate_keyfile_ext: ".key"
  cert_days_renewal: "20-30"
  cmd_enabled: true
  post_cmd_run: "systemctl reload nginx"
  post_cmd_timeout: 60
  revoke_on_update: false
  revoke_on_delete: false

certificate:
  - domain: "example.com"
    issuer: "letsencrypt"
    dns_challenge: "cloudflare"
    san: "www.example.com,api.example.com"
    renewal_days: "30"
    bundle: true
    key_type: "RSA2048"

storage:
  vault:
    url: "https://vault.example.com"
    role_id: "your-role-id"
    secret_id: "your-secret-id"
```

### Running the Client

```bash
acme-manager-client \
  -client.config-path=client-config.yml \
  -client.manager-url=https://acme-manager.example.com \
  -client.manager-token=your-bearer-token \
  -client.check-config-interval=5m
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
| `renewal_days` | string | "20-30" | Days before expiration to renew |
| `bundle` | bool | false | Include CA chain in certificate |
| `key_type` | string | "RSA2048" | Private key type (RSA2048, RSA4096, EC256, EC384) |

### Client Deployment Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `certificate_deploy` | bool | false | Deploy certificates locally |
| `certificate_dir` | string | "" | Directory for certificate deployment |
| `certificate_dir_perm` | octal | 0700 | Directory permissions |
| `certificate_file_perm` | octal | 0600 | Certificate file permissions |
| `certificate_keyfile_perm` | octal | 0600 | Private key file permissions |
| `cmd_enabled` | bool | false | Enable command execution |
| `post_cmd_run` | string | "" | Command to run after deployment |
| `post_cmd_timeout` | int | 60 | Command timeout in seconds |
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

**Version**: 0.6.1+  
**Last Updated**: October 2025