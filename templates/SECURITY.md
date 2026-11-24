# Security Policy

## Supported Versions

Only the latest release on the default branch (`main`) receives security updates.

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues.

Instead, report them responsibly via:
- GitHub Private Vulnerability Reporting (Security tab -> Advisories -> Report a vulnerability), or
- Direct private contact with the repository maintainer.

Include:
1. A clear description of the vulnerability and affected component/URL.
2. Steps to reproduce (minimal proof of concept without destructive actions).
3. Potential impact and any suggested remediation.

We aim to acknowledge reports within 48 hours and provide an initial assessment within 5 business days.

## Security Audit Baseline

This repository follows the **Web Security Audit System (WSAS)** baseline:
- Automated secret scanning, dependency auditing, and static analysis on every push and pull request.
- Release gate blocks deployment if any unresolved `Critical` or `High` vulnerability is present.
- Secrets and private keys must never be committed to source control or sent to external AI services.
