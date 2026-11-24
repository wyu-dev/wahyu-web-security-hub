# Security Policy — `wahyu-web-security-hub`

This repository is the central **Web Security Audit System (WSAS)** hub.

## Security Guarantees

- All third-party GitHub Actions are pinned to verified 40-character commit SHAs.
- Automated secret redaction ensures credentials are never persisted in generated reports or sent to external AI providers.
- Test fixtures in `tests/fixtures/` contain only synthetic non-functional patterns clearly marked for unit verification.

## Reporting a Vulnerability

Please report vulnerabilities privately via GitHub Security Advisories rather than public issues.
