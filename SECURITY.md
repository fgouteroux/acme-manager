# Security Policy

## Supported versions

Security fixes are applied to the latest released version. Older tags are not
patched; please upgrade before reporting an issue against them.

| Version | Supported |
|---------|-----------|
| latest release | yes |
| older releases | no |

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue.

Use [GitHub private vulnerability reporting](https://github.com/fgouteroux/acme-manager/security/advisories/new),
which notifies the maintainer directly and keeps the discussion confidential
until a fix is available.

Include, as far as you can determine it:

- the affected version or commit
- the component involved (server, client, ring, Vault storage, an ACME issuer)
- what an attacker can achieve, and what access they need to start
- steps to reproduce, ideally with a minimal configuration

You should get an acknowledgement within a few days. This is a single-maintainer
project, so please allow reasonable time for a fix before disclosing publicly.

## Scope

ACME Manager issues and deploys TLS certificates, holds bearer tokens for its
API, and stores private keys in Vault. Reports that are especially relevant:

- authentication or authorisation bypass on the HTTP API
- exposure of private keys, token values, or Vault credentials, including
  through logs
- a certificate being issued for, or delivered to, a party that does not own the
  domain
- path traversal or injection through certificate, issuer or owner names
- cluster-level issues where one node can be made to act on another's behalf

Out of scope: findings that require an already-compromised host or a valid
administrative API key, vulnerabilities in a dependency that are not reachable
from this code, and static-analysis reports without a demonstrated impact.
