# WSAS Risk Rating, Scoring & Release Gate Specification

## 1. Severity Classification

| Severity | Definition & Concrete Examples | Mandatory Policy Action |
| :--- | :--- | :--- |
| **Critical** | Immediate full compromise, exposed private key / service account / `service_role` key, unrestricted database write (`allow read, write: if true`), unauthenticated admin bypass, RCE. | **BLOCK deployment immediately.** Rotate exposed credentials and fix before any release. |
| **High** | Serious unauthorized data exposure or privilege escalation: missing Supabase RLS, auth-only Firestore writes without ownership check, SQL injection, `APP_DEBUG=true` in production, High/Critical vulnerable dependencies, `USER_DEPLOYING` + `ANYONE_ANONYMOUS` GAS app performing writes. | **BLOCK deployment.** Fix and retest before release. |
| **Medium** | Exploitable or high-risk weaknesses requiring context confirmation: DOM XSS (`innerHTML`, `dangerouslySetInnerHTML`, `{!! ... !!}`), unescaped GAS `<?!= ... ?>`, `$guarded = []`, overly broad OAuth scopes, public read rules on uncertain collections. | **Fix before release** (or document explicit risk acceptance with mitigation). |
| **Low** | Defense-in-depth & hygiene gaps: missing SRI on external CDN scripts, `target="_blank"` without `noopener`, missing CSP header, unpinned GitHub Action tags. | **Track in backlog** and resolve in regular maintenance. |
| **Info** | Informational hardening context: public Firebase web client `apiKey` (normal by design; verify HTTP referrer restrictions), architecture hardening tips. | **Informational / optional hardening.** |

## 2. Dual Status System: Security Score vs Release Gate

WSAS deliberately separates maturity measurement from deployment eligibility:

### A. Security Score (0–100)
Starts at `100`, with point deductions per confirmed finding:
- `Critical`: `-25`
- `High`: `-15`
- `Medium`: `-7`
- `Low`: `-2`
- `Info`: `0`
- Clamped to `[0, 100]`.

### B. Release Gate (`PASS` / `WARN` / `BLOCK`)
- **`BLOCK`**: Any `Critical >= 1` **OR** `High >= 1`.
- **`WARN`**: `Critical == 0` AND `High == 0` AND `Medium >= 1`.
- **`PASS`**: `Critical == 0` AND `High == 0` AND `Medium == 0`.

> **Golden Rule:** A Security Score of `85/100` (e.g., 1 `High` finding) or `75/100` (1 `Critical` finding) **STILL BLOCKS DEPLOYMENT**. Never cite a high numeric score as proof that an application is safe.

## 3. Honest Scanner Coverage

Every report must declare `scanner_coverage`:
- **`COMPLETE`**: All applicable scanners executed cleanly.
- **`PARTIAL (missing: ...)`**: One or more applicable scanners were `not_installed` or errored. A `PASS` gate with `PARTIAL` coverage means "no issues found by the checks that ran", NOT full clearance.
