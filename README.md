# acme_manager

ACME Manager is a tool designed to create, manage, and deploy ACME certificates on servers. It handles automatic renewal, monitors expiration dates, and ensures seamless deployment for applications or proxies.

![Acme Manager](img/home.png)

## Features

- **Certificate Management**: Automatically renew certificates 30 days before expiration.
- **Cluster Mode**: Operates in a cluster using the Memberlist protocol with automatic leader election.
- **Vault Storage**: Stores certificates securely in Vault.
- **DNS/HTTP Challenges**: Supports both challenge methods for domain validation.
- **Metrics and Monitoring**: Provides application prometheus metrics and a web UI for certificate management.
- **Automatic refresh**: Configuration file are periodically refreshed without any service restart.
- **Client Local Certificate**: Ensure that client local certificate deployed are always up-to-date.
- **Client Local Cmd Run**: Run a custom command once certificate have been created/updated/renewed/deployed on the client.

## How It Works

1. ACME Manager creates certificates using [ACME](https://datatracker.ietf.org/doc/html/rfc8555).
2. Certificates are stored securely in Vault.
3. The application monitors expiration dates and renews certificates as needed. (by default between 20-30d before expiration)


### Usage

```
Usage of acme-manager-server:

ACME Manager Server - Manages ACME certificates in cluster mode
Version: (version=v0.5.1-next, branch=main, revision=29075921bf870fcf3a769ea2758b3e3fd279271d)

Flags:
  -check-config-interval duration
        Time interval to check if config file changes. (default "30s")
  -check-issuer-interval duration
        Time interval to check issuer health. (default "10m0s")
  -check-renewal-interval duration
        Time interval to check if certificate renewal needed. (default "30m0s")
  -check-token-interval duration
        Time interval to check if tokens expired. (default "1m0s")
  -cleanup
        Enables cleanup in vault and CA Issuers.
  -cleanup.cert-expire-days int
        Number of days before old certificate expires to revoke and delete vault secret version. (default "10")
  -cleanup.cert-revoke-last-version
        Revoke last certificate version and delete vault secret version.
  -cleanup.interval duration
        Time interval to scan vault secret certificates and cleanup if needed. (default "1h0m0s")
  -config-path string
        Config path. (default "config.yml")
  -env-config-path string
        Environment vars config path. (default ".env")
  -log.format string
        Output format of log messages. One of: [logfmt, json]. (default "logfmt")
  -log.level string
        Only log messages with the given severity or above. One of: [debug, info, warn, error]. (default "info")
  -ring.instance-addr string
        IP address to advertise in the ring. Default is auto-detected.
  -ring.instance-id string
        Instance ID to register in the ring.
  -ring.instance-port int
        Port to advertise in the ring. (default "7946")
  -ring.join-members string
        Other cluster members to join. Comma-separated list of addresses.
  -server.http-read-header-timeout int
        Read timeout for HTTP request headers. (default "10")
  -server.http-read-timeout int
        Read timeout for entire HTTP request, including headers and body. (default "300")
  -server.listen-address string
        Server listen address. (default ":8989")
  -server.tls-cert-file string
        Server tls certificate file.
  -server.tls-client-ca-file string
        Root certificate authority used to verify client certificates.
  -server.tls-key-file string
        Server tls key file.
  -version
        Show version information

For all flags including advanced memberlist configuration options, use: --help-all
```

### High availability with clustering

Acme Manager run in cluster with the memberlist protocol.

![Memberlist](img/memberlist.png)

One instance of the ring is elected to be the leader and this is the only one which will make request to acme servers, store certificate in vault and store non-sensitive data in the key value store of the ring.

If the leader instance goes down, another one will be elected and will start to manage certificates.

### Env File

Acme Manager load environment variables from .env file.
It's use to configure the dns challenge as lego library need it.

### Config file

Any valid acme issuers could be added in issuer block.

Private keys must exists for each given issuer in `rootpath_account`, here:
- /tmp/accounts/sectigo/private_key.pem
- /tmp/accounts/letsencrypt/private_key.pem

```
common:
  api_key_hash: 123abc456def
  rootpath_account: /tmp/accounts
  rootpath_certificate: /tmp/certificates

issuer:
  sectigo:
    ca_dir_url: https://acme.sectigo.com/v2/OV
    eab: true
    kid: kid_value
    hmac: hmac_value
  letsencrypt:
    ca_dir_url: https://acme-staging-v02.api.letsencrypt.org/directory

storage:
  vault:
    role_id: "role_id_value"
    secret_id: "secret_id_value"
    url: " https://vault.example.com"
    secret_engine: "myengine"
    certificate_prefix: "certificates"
    token_prefix: "tokens"
    mount_path: "login/approle"
```

Required Common parameters:
- **api_key_hash** (string): the api key hash used to manage tokens.
- **rootpath_account** (string): path to find issuer private keys and account file
- **rootpath_certificate** (string): path to temporary store certificate file before storing in vault.

Optional Common parameters:
- **cert_days_renewal** (int): Number of days before certificate should be renewed (default: 20-30).
- **plugins** (array of hash):
    - **name** (required, string): the name of the plugin
    - **path** (required, string): the path of the plugin
    - **checksum** (optional, string): the checksum of the plugin to prevent execution if not match
    - **timeout** (optional, int): the timeout for the plugin execution before kill process
    - **env** (optional, string): the environment vars for the plugin execution

Optional Issuer parameters:
- **eab** (bool): Use External Account Binding for account registration. Requires `kid` and `hmac`.
- **kid** (string): Key identifier from External CA. Used for External Account Binding
- **hmac** (string): MAC key from External CA. Should be in Base64 URL Encoding without padding format. Used for External Account Binding.
- **http_challenge** (string): http challenge name to use for domain validation
- **dns_challenge** (string): dns challenge name to use for domain validation
- **contact** (string): email used for registration and recovery contact
- **overall_request_limit** (int): ACME overall requests limit
- **certificate_timeout** (int): set the certificate timeout value in seconds when obtaining a certificate
- **unregister** (bool): deletes the account registration from issuer. ACME does not provide a way to reactivate a deactivated account. If you want to register an account you must use a new private key.

### Plugins

Acme Manager supports plugins execution before creating certificates. This allow to perform some action like creating DNS CAA record, or any necessary actions before requesting certificate. A plugin could be a binary or any executable file, and require to support cmd argument in this order: domain, issuer, challenge. Example: /my-plugin-path/dns-acme-manager-plugin testfgx.example.com letsencrypt dns

### Server Mode

Manage certificate with API endpoints in a secured way.

| HTTP Method            | Endpoint                     |  Auth Type Supported       |
|------------------------|------------------------------|----------------------------|
| GET                    | /api/v1/certificate/metadata | Bearer Token               |
| GET, POST, PUT, DELETE | /api/v1/certificate          | Bearer Token               |
| GET, POST, PUT, DELETE | /api/v1/token                | API key Header             |

See swagger page: http://localhost:8989/swagger/index.html

#### Generate an API key:
```
# Generate a random string
API_KEY=$(openssl rand -base64 32)

# Hash the random string with SHA1 and put it in the `api_key_hash` of acme manager config
$ echo -n $API_KEY | sha1sum
96a0585f6d3c3f90f74cdb963e7664f2ee8a10bb  -

# Your API KEY to use for curl command and others.
$ echo $API_KEY
GMZgFB3nYxTgISIqr8YAezgNpxePJqgOeU9o3/JRwS8=

```

#### Token endpoint

Required parameters:  
- **username** (string): token username
- **scope** (list of string): token scope

Optional parameters:
- **expires** (string): token duration (if not set, expires never)

##### Obtain a new token:
```
curl -XPOST \
  'http://localhost:8989/api/v1/token' \
  -H "X-API-Key: GMZgFB3nYxTgISIqr8YAezgNpxePJqgOeU9o3/JRwS8=" \
  -d '{
  "username":"testfgx",
  "scope":["read","create","update","delete"]
}'

{
  "expires": "Never",
  "id": "94e0c649-de98-476a-a5cc-ff1201512605",
  "scope": [
    "read",
    "create",
    "update",
    "delete"
  ],
  "token": "OTRlMGM2NDktZGU5OC00NzZhLWE1Y2MtZmYxMjAxNTEyNjA1OkczdTFUSkUtc1FCM05veEhtQXNVcW0xYXd4OXp4Z19V",
  "tokenHash": "2fba65b7e4c953148427407cd556c9b49043e1a4",
  "username": "testfgx"
}
```

##### Update the token scope and add expiration time to 30days
```
curl -XPUT \
  'http://localhost:8989/api/v1/token' \
  -H "X-API-Key: GMZgFB3nYxTgISIqr8YAezgNpxePJqgOeU9o3/JRwS8=" \
  -d '{
  "id": "94e0c649-de98-476a-a5cc-ff1201512605",
  "username":"testfgx",
  "scope":["read"], "expires":"30d"}
}'

{
  "expires": "2025-02-09 11:09:01 +0000 UTC",
  "id": "94e0c649-de98-476a-a5cc-ff1201512605",
  "scope": [
    "read"
  ],
  "token": "OTRlMGM2NDktZGU5OC00NzZhLWE1Y2MtZmYxMjAxNTEyNjA1OmpTeGtoUUwzd0MwQWl4Vzk1aU9mVjM4RzdIbWwzQ0F6",
  "tokenHash": "e7bf79d0b679fe56014cb8e87358ac459880f6dd",
  "username": "testfgx"
}
```

##### Read the token (no token value, contain only the hash)
```
curl -XGET \
  'http://localhost:8989/api/v1/token/94e0c649-de98-476a-a5cc-ff1201512605' \
  -H "X-API-Key: GMZgFB3nYxTgISIqr8YAezgNpxePJqgOeU9o3/JRwS8="

{
  "hash": "e7bf79d0b679fe56014cb8e87358ac459880f6dd",
  "scope": [
    "read"
  ],
  "username": "testfgx",
  "expires": "2025-02-09 11:09:01 +0000 UTC"
}
```

##### Revoke the token
```
curl -XDELETE \
  'http://localhost:8989/api/v1/token/94e0c649-de98-476a-a5cc-ff1201512605' \
  -H "X-API-Key: GMZgFB3nYxTgISIqr8YAezgNpxePJqgOeU9o3/JRwS8=" \
```

#### Certificate endpoint

Required parameters:  
- **domain** (string): domain certificate
- **issuer** (string): issuer certificate
- **csr** (string): certificate signing request in PEM format and base64 encoded

Optional parameters:
- **bundle** (bool): if true, add the issuers certificate to the new certificate
- **renewal_days** (string): number of days or interval of days before automatic certificate renewal
- **days** (int): number of days before certificate expiration
- **san** (string, comma separated): DNS domain names to add to certificate
- **http_challenge** (string): http challenge name to use for domain validation
- **dns_challenge** (string): dns challenge name to use for domain validation
- **profile** (string): ACME profile for certificate issuance (requires CA support for draft-aaron-acme-profiles)


##### Get the certificate
```
curl -X 'GET' \
  'http://localhost:8989/api/v1/certificate/letsencrypt/testfgx01.example.com' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer MDIxYjUwNzUtMmQ....'

{
  "cert": "-----BEGIN CERTIFICATE-----\nMIIFUT...\n-----END CERTIFICATE-----\n",
  "csr": "LS0...",
  "ca_issuer": "\n-----BEGIN CERTIFICATE-----\nMIIFTT...\n-----END CERTIFICATE-----\n",
  "issuer": "letsencrypt",
  "url": "https://acme-staging-v02.api.letsencrypt.org/acme/cert/2b8cfad6a7516ac17349...",
  "domain": "testfgx01.example.com",
  "owner": "testfgx"
}
```

##### Obtain a new certificate

```
curl -X 'POST' \
  'http://localhost:8989/api/v1/certificate' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer MDIxYjUwNzUtMmQ....' \
  -H 'Content-Type: application/json' \
  -d '{
  "dns_challenge": "ns1",
  "domain": "testfgx01.example.com",
  "issuer": "letsencrypt",
  "renewal_days": "30",
  "csr": "LS0..."
}'

{
  "cert": "-----BEGIN CERTIFICATE-----\nMIIFUT...\n-----END CERTIFICATE-----\n",
  "csr": "LS0...",
  "ca_issuer": "\n-----BEGIN CERTIFICATE-----\nMIIFTT...\n-----END CERTIFICATE-----\n",
  "issuer": "letsencrypt",
  "url": "https://acme-staging-v02.api.letsencrypt.org/acme/cert/2b8cfad6a7516ac17349...",
  "domain": "testfgx01.example.com",
  "owner": "testfgx"
}
```

##### Update a certificate (will revoke the old one and create a new one)

```
curl -X 'PUT' \
  'http://localhost:8989/api/v1/certificate' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer MDIxYjUwNzUtMmQ....' \
  -H 'Content-Type: application/json' \
  -d '{
  "dns_challenge": "ns1",
  "domain": "testfgx01.example.com",
  "issuer": "letsencrypt",
  "renewal_days": "30",
  "san": "testfgx02.example.com",
  "csr": "LS0..."
}'

{
  "cert": "-----BEGIN CERTIFICATE-----\nMIIFUT...\n-----END CERTIFICATE-----\n",
  "csr": "LS0...",
  "ca_issuer": "\n-----BEGIN CERTIFICATE-----\nMIIFTT...\n-----END CERTIFICATE-----\n",
  "issuer": "letsencrypt",
  "url": "https://acme-staging-v02.api.letsencrypt.org/acme/cert/2b8cfad6a7516ac17349...",
  "domain": "testfgx01.example.com",
  "owner": "testfgx"
}
```

##### Revoke a certificate

```
curl -X 'DELETE' \
  'http://localhost:8989/api/v1/certificate/letsencrypt/testfgx01.example.com' \
  -H 'accept: application/json' \
  -H 'Authorization: Bearer MDIxYjUwNzUtMmQ....'
```

Token and certificate are retrieved from vault for each get api call.


### Client Mode

Acme manager could run in client mode to obtain certificate from acme manager server.

It need the acme manager server url and a token.

The client start with reading the config file, check certificates from acme manager server and deploy them.
It regulary check if certificate have been renewed/changed and redeploy them.

Local certificate deployment are controlled by `certificate_deploy` in common block.

It is also possible to execute a custom command once certificate have been generated/revoked wih `cmd_enabled`.

The client start a webserver to expose some metrics.

```
Usage of acme-manager-client:

ACME Manager Client - Manages local certificates from cluster
Version: (version=v0.5.1-next, branch=main, revision=29075921bf870fcf3a769ea2758b3e3fd279271d-modified)

Flags:
  -client.check-config-interval duration
      Time interval to check if client config file changes and to update local certificate file. (default 5m0s)
  -client.config-path string
      Client config path. (default "client-config.yml")
  -client.manager-token string
      Client manager token (can be set via ACME_MANAGER_TOKEN env var).
  -client.manager-url string
      Client manager URL (can be set via ACME_MANAGER_URL env var). (default "http://localhost:8989/api/v1")
  -client.pull-only
      Set client in pull mode. Manage local certificate files based on remote server changes.
  -client.tls-ca-file string
      Client manager tls ca certificate file.
  -client.tls-cert-file string
      Client manager tls certificate file.
  -client.tls-key-file string
      Client manager tls key file.
  -client.tls-skip-verify
      Client manager tls skip verify.
  -log.format string
      Output format of log messages. One of: [logfmt, json]. (default "logfmt")
  -log.level string
      Only log messages with the given severity or above. One of: [debug, info, warn, error]. (default "info")
  -server.http-read-header-timeout int
      Read timeout for HTTP request headers. (default 10)
  -server.http-read-timeout int
      Read timeout for entire HTTP request, including headers and body. (default 300)
  -server.listen-address string
      Server listen address. (default ":8989")
  -server.tls-cert-file string
      Server tls certificate file.
  -server.tls-key-file string
      Server tls key file.
  -version
      Show version information
```

Example:
```
$ acme_manager -client.config-path config.yml

ts=2025-01-10T10:18:49.077Z caller=client.go:40 level=info msg="Checking certificates from config file"
ts=2025-01-10T10:18:49.165Z caller=client.go:224 level=info msg="Deployed certificate /etc/myapp/ssl/letsencrypt/testfgx01.example.com.crt"
ts=2025-01-10T10:18:49.165Z caller=client.go:233 level=info msg="Deployed private key /etc/myapp/ssl/letsencrypt/testfgx01.example.com.key"
ts=2025-01-10T10:18:49.173Z caller=cmd.go:29 level=info msg="Command '/usr/bin/systemctl reload myapp' successfully executed"
ts=2025-01-10T10:18:49.174Z caller=main.go:269 level=info msg="Listening on" address=:8989
ts=2025-01-10T10:18:49.174Z caller=main.go:271 level=info msg="TLS is disabled." address=:8989

```

#### Client Certificate config file

Optional Common parameters:
- **certificate_deploy** (bool): If set to true, deploy certificate and private key in given `certificate_dir`
- **certificate_backup** (bool): If set to true, backup certificate and private key in given storage `vault` config
- **certificate_dir** (string): Directory in which to deploy issuers certificates and private keys
- **certificate_dir_perm** (uint32): Unix permission for certificate directory in octal format (default: 0700)
- **certificate_file_perm** (uint32): Unix permission for certificate file in octal format (default: 0600)
- **certificate_keyfile_perm** (uint32): Unix permission for certificate key file in octal format (default: 0600)
- **certificate_file_ext** (string): certificate file extension (default: ".crt")
- **certificate_keyfile_ext** (string): certificate key file extension (default: ".key")
- **certificate_ca_file_ext** (string): CA chain file extension, used when bundle=false (default: ".ca.crt")
- **certificate_keyfile_no_generate** (bool): It set to true, don't auto generate private key, use provided file (default: false)
- **cmd_enabled** (bool): If set to true, allow running pre and post command.
- **pre_cmd_run** (string): Pre Command to run before executing certificate changes.
- **pre_cmd_timeout** (int): Pre Command timeout (default: 60)
- **post_cmd_run** (string): Post Command to run after executing certificate changes.
- **post_cmd_timeout** (int): Post Command timeout (default: 60)
- **revoke_on_update** (bool): If set to true, revoke the old certificate on update (default: false)
- **revoke_on_delete** (bool): If set to true, revoke the certificate on delete (default: false)
- **delay_before_delete** (string): If set, define a duration to wait before deleting certificate
 
Optional Certificate parameters:
- **bundle** (bool): if true, add the issuers certificate to the new certificate. When false, CA chain is saved as a separate file (domain.ca.crt)
- **renewal_days** (string): number of days or interval of days before automatic certificate renewal. For short-lived certificates (where renewal window exceeds certificate lifetime), the system automatically switches to percentage-based renewal (50-75% of lifetime)
- **days** (int): number of days before certificate expiration
- **san** (string, comma separated): DNS domain names to add to certificate
- **http_challenge** (string): http challenge name to use for domain validation
- **dns_challenge** (string): dns challenge name to use for domain validation
- **key_type** (string): Key type to use for private keys. Supported: rsa2048, rsa3072, rsa4096, rsa8192, ec256, ec384
- **labels** (key=value string, comma separated): labels to attach to the certificate, used by the metric `acme_manager_certificate_expiry`
- **profile** (string): ACME profile for certificate issuance. Useful for CAs supporting custom certificate profiles (e.g., Sectigo with specific Key Usage requirements)


```
common:
  certificate_deploy: true
  certificate_backup: true
  certificate_dir: /etc/myapp/ssl/

  cmd_enabled: true
  post_cmd_run: /usr/bin/systemcl reload myapp
  post_cmd_timeout: 30

storage:
  vault:
    role_id: "role_id_value"
    secret_id: "secret_id_value"
    url: " https://vault.example.com"
    secret_engine: "myengine"
    certificate_prefix: "backup/certificates"
    mount_path: "login/approle"

certificate:
  - domain: testfgx01.example.com
    issuer: letsencrypt

  - domain: testfgx02.example.com
    issuer: sectigo
    bundle: false  # CA chain saved as testfgx02.example.com.ca.crt

  - domain: testfgx03.example.com
    issuer: sectigo
    profile: "custom-profile"  # Use custom ACME profile (requires CA support)
```

### DNS and HTTP Challenge

acme-manager support DNS and HTTP challenge (thanks to lego lib).

#### HTTP Challenge

- [memcached](https://github.com/go-acme/lego/blob/master/providers/http/memcached/memcached.go)
- [s3](https://github.com/go-acme/lego/blob/master/providers/http/s3/s3.go)
- [webroot](https://github.com/go-acme/lego/blob/master/providers/http/webroot/webroot.go)
- [acme-manager kvring](https://github.com/fgouteroux/acme-manager/blob/main/certstore/http_challenge.go)

The acme-manager `kvring` challenge, allow HTTP domain validation with the embedded HTTP endpoint in acme manager.

Setting the `http_challenge: kvring`, will store the challenge token in kvring and it could be retrieved with a call like:
```
curl http://testfgx01.example.com/.well-known/acme-challenge/NClsmGOVJqV9jx8xBLO6kabcxBufpLGcu5oUjjhhu1o
```

Once the domain is validated, the challenge token value is removed from kvring.

#### DNS Challenge

All DNS Providers from lego lib.

For environment vars available for each DNS provider, check the [lego page](https://go-acme.github.io/lego/dns/).

Example for [NS1](https://go-acme.github.io/lego/dns/ns1/):

- `NS1_API_KEY="secretapikey"`
- `NS1_TTL="120"`
- `NS1_HTTP_TIMEOUT="10"`
- `NS1_POLLING_INTERVAL="2"`
- `NS1_PROPAGATION_TIMEOUT="60"`

Environment vars available to customize the dns check:

- `ACME_MANAGER_DNS_PROPAGATIONDISABLEANS`: By setting this var to true, disables the need to await propagation of the TXT record to all authoritative name servers.
- `ACME_MANAGER_DNS_PROPAGATIONRNS`: By setting this var to true, use all the recursive nameservers to check the propagation of the TXT record.
- `ACME_MANAGER_DNS_PROPAGATIONWAIT`: By setting this var, disables all the propagation checks of the TXT record and uses a wait duration instead.
- `ACME_MANAGER_DNS_RESOLVERS`: Set the resolvers to use for performing DNS requests, by default it is the authoritative DNS server
- `ACME_MANAGER_DNS_TIMEOUT`: the DNS timeout value in seconds when performing authoritative name server queries, (default: "10").

### Managed certificate web UI

The endpoint http://localhost:8989/certificates return the page for all managed certificate.

### Managed token web UI

The endpoint http://localhost:8989/tokens return the page for all managed tokens.

### Metrics Exposed

**App metrics**

This endpoint return metrics about app itself.

```
# HELP acme_manager_build_info A metric with a constant '1' value labeled by version, revision, branch, goversion from which acme_manager was built, and the goos and goarch for the build.
# TYPE acme_manager_build_info gauge
acme_manager_build_info{branch="HEAD",goarch="amd64",goos="linux",goversion="go1.22.10",revision="f9b7946ad9150bfd1e9b19ff5d1f8b47ceffdbc3",tags="unknown",version="0.1.5"} 1
# HELP acme_manager_certificate_created_total Number of created certificates by issuer and owner
# TYPE acme_manager_certificate_created_total counter
acme_manager_certificate_created_total{issuer="letsencrypt",owner="testfgx"} 1
acme_manager_certificate_created_total{issuer="sectigo",owner="testfgx"} 1
# HELP acme_manager_certificate_revoked_total Number of revoked certificates by issuer and owner
# TYPE acme_manager_certificate_revoked_total counter
acme_manager_certificate_revoked_total{issuer="sectigo",owner="testfgx"} 1
# HELP acme_manager_certificate_total Number of managed certificates by issuer and owner
# TYPE acme_manager_certificate_total gauge
acme_manager_certificate_total{issuer="letsencrypt",owner="testfgx"} 1
acme_manager_certificate_total{issuer="sectigo",owner="testfgx"} 1
# HELP acme_manager_issuer_config_error 1 if there was an error with issuer config, 0 otherwise
# TYPE acme_manager_issuer_config_error gauge
acme_manager_issuer_config_error{issuer="letsencrypt"} 0
acme_manager_issuer_config_error{issuer="sectigo"} 0
# HELP acme_manager_vault_delete_secret_success_total Number of created vault secrets
# TYPE acme_manager_vault_delete_secret_success_total counter
acme_manager_vault_delete_secret_success_total 1
# HELP acme_manager_vault_get_secret_success_total Number of retrieved vault secrets
# TYPE acme_manager_vault_get_secret_success_total counter
acme_manager_vault_get_secret_success_total 5
# HELP acme_manager_vault_put_secret_success_total Number of created/updated vault secrets
# TYPE acme_manager_vault_put_secret_success_total counter
acme_manager_vault_put_secret_success_total 2
```

### Limitations

Currently only vault storage with app role login is supported.

### TLS and basic authentication

Acme Manager supports TLS and basic authentication. This enables better control of the various HTTP endpoints.

To use TLS and/or basic authentication, you need to pass a configuration file using the `--web.config.file` parameter. The format of the file is described
[in the exporter-toolkit repository](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md).

### Sources

- [Lego](https://github.com/go-acme/lego)
- [Hashicorp Memberlist](https://github.com/hashicorp/memberlist)
- [Grafana Distributed systems kit](https://github.com/grafana/dskit)
