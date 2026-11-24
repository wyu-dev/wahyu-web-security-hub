# Web Security Audit Report — `react-firebase-vuln`

- **Generated (UTC):** `2026-11-24T13:25:17Z`
- **Audit Mode:** `manual-local`
- **Release Gate:** **`BLOCK`**
- **Security Score:** `62/100` *(informational — a high score never overrides a Critical/High release block)*
- **Scanner Coverage:** `PARTIAL (missing: gitleaks/betterleaks, semgrep)`

> **Gate Decision:** Deployment BLOCKED — resolve all Critical and High findings and retest before release.

## 1. Project Detection & Audit Profile

| Dimension | Detected Value |
| :--- | :--- |
| Frontend | React / Vite |
| Backend | Firebase |
| Database | Firestore |
| Authentication | Firebase Auth |
| Hosting | GitHub Pages / Static Hosting |
| Profiles Applied | `static-web, react-node, firebase` |
| Files Inspected | 5 |

## 2. Severity Summary

| Severity | Count | Policy Action |
| :--- | :---: | :--- |
| **Critical** | 1 | Block deployment immediately |
| **High** | 0 | Block deployment |
| **Medium** | 1 | Fix before release |
| **Low** | 3 | Track in backlog |
| **Info** | 0 | Hardening recommendation |
| **Total** | **5** | |

## 3. Tool Execution Ledger (Honest Coverage)

| Tool | Status | Notes |
| :--- | :--- | :--- |
| `wsas-static-checks` | `executed` | Profiles applied: static-web,react-node,firebase |
| `gitleaks/betterleaks` | `not_installed` | Install Gitleaks (winget install Gitleaks.Gitleaks) or Betterleaks for full history & entropy secret scanning. |
| `npm-audit` | `skipped_not_applicable` | No package-lock.json present in target project. |
| `composer-audit` | `skipped_not_applicable` | No composer.lock present in target project. |
| `semgrep` | `not_installed` | Not installed locally. Use GitHub Actions reusable workflow or install Semgrep CLI. |
| `owasp-zap` | `skipped_not_applicable` | Passive DAST requires an authorized running staging URL (never run active scans on production without explicit approval). |

## 4. Evidence-Backed Findings

### 1. [Critical] Unrestricted public write access in firestore.rules (allow ...: if true)
- **Rule / Tool:** `FB-RULES-001` via `wsas-static-checks` (CWE-284)
- **Category:** Firebase Security
- **Location:** `firestore.rules:5`
- **Evidence (Redacted):** `allow read, write: if true;`
- **Recommended Remediation:** Replace `if true` with least-privilege authentication, ownership (`request.auth.uid == userId`), role checks, and schema validation.

### 2. [Medium] React dangerouslySetInnerHTML used without visible DOMPurify sanitization
- **Rule / Tool:** `REACT-XSS-001` via `wsas-static-checks` (CWE-79)
- **Category:** Cross-Site Scripting (XSS)
- **Location:** `src/NoticeBanner.jsx:7`
- **Evidence (Redacted):** `dangerouslySetInnerHTML={{ __html: htmlMessage }}`
- **Recommended Remediation:** Avoid `dangerouslySetInnerHTML` or sanitize content strictly via `DOMPurify.sanitize(...)`.

### 3. [Low] GitHub Action 'actions/checkout' is pinned to mutable ref '@v4' instead of a 40-char commit SHA
- **Rule / Tool:** `CI-PIN-001` via `wsas-static-checks` (CWE-829)
- **Category:** CI/CD Supply Chain
- **Location:** `.github/workflows/deploy.yml:7`
- **Evidence (Redacted):** `- uses: actions/checkout@v4`
- **Recommended Remediation:** Pin third-party GitHub Actions and reusable workflows to verified full 40-character commit SHAs with a version comment.

### 4. [Low] External CDN script loaded without Subresource Integrity (integrity attribute)
- **Rule / Tool:** `STATIC-SRI-001` via `wsas-static-checks` (CWE-353)
- **Category:** Supply Chain Security
- **Location:** `index.html:6`
- **Evidence (Redacted):** `<script src="https://cdn.example.com/analytics.js"></script>`
- **Recommended Remediation:** Add `integrity="sha384-..." crossorigin="anonymous"` or bundle the dependency locally.

### 5. [Low] Link opens new tab (target="_blank") without rel="noopener noreferrer"
- **Rule / Tool:** `STATIC-TARGET-001` via `wsas-static-checks` (CWE-1022)
- **Category:** Browser Security
- **Location:** `index.html:10`
- **Evidence (Redacted):** `<a href="https://example.org" target="_blank">External Docs</a>`
- **Recommended Remediation:** Add `rel="noopener noreferrer"` to external links using `target="_blank"`.

## 5. Self-Refinement Verification Checklist

- [ ] Confirm each finding against actual trust boundaries and business logic.
- [ ] Obtain explicit human approval before applying patches or modifying database rules.
- [ ] Apply minimal, targeted fixes without exposing secrets.
- [ ] Re-run scanners (`Retest`) and attach fresh proof that findings are resolved.
- [ ] Verify no regressions or new vulnerabilities were introduced (`Verify`).
