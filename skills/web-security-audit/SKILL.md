---
name: web-security-audit
description: >-
  Use this skill whenever the user asks to perform a web security audit, vulnerability
  assessment, secret scan, Firebase/Supabase rules audit, Google Apps Script security check,
  Laravel/PHP security review, pre-release security gate check, or security hardening on a
  web project hosted on GitHub. Follows an evidence-backed Scan -> Analyse -> Fix -> Retest -> Verify loop.
---

# Web Security Audit (WSAS)

Perform a structured, evidence-backed web application security audit modeled on a security
engineer workflow. Never rely solely on AI intuition: combine automated scanners, stack-aware
configuration checks, contextual threat analysis, and mandatory retest verification.

## Hard Safety & Integrity Rules

1. **Never fabricate scanner results.** If a tool (`gitleaks`, `betterleaks`, `semgrep`, `npm audit`, `composer audit`, `owasp-zap`) is not installed or skipped, record its status honestly as `not_installed` or `skipped_not_applicable`.
2. **Every finding requires evidence.** Always cite exact `file:line` (or URL/target), tool/rule ID, CWE where applicable, and redacted proof.
3. **Never expose raw secrets.** Redact all API keys, tokens, passwords, private keys, and connection strings before printing logs, writing reports, or calling any external AI provider.
4. **Never auto-modify production code or database rules without approval.** Present proposed minimal patches and wait for explicit human approval before editing code, Firestore/Storage rules, Supabase SQL policies, or deployment configs.
5. **Never run active/destructive DAST against production.** Passive OWASP ZAP baseline scans are permitted only against authorized staging/local URLs. Active scans require explicit written authorization.
6. **Release Gate overrides Security Score.** Even a score of `85/100` is **`BLOCK`** if any `Critical` or `High` issue remains open.
7. **No "fixed" claim without Retest proof.** Changing code is not proof of remediation; always re-run the relevant scanner/check and verify zero regressions.

## References (Progressive Disclosure)

Read these references when needed for detailed criteria:
- [Security Checklists by Stack](./references/checklist.md)
- [Severity Rubric, Scoring & Release Gate](./references/risk-rating.md)
- [Report Schema & Redaction Rules](./references/report-template.md)

## Audit Procedure (Security Self-Refinement Loop)

### Step 1 — Scan (Reconnaissance + Evidence Collection)

Run the WSAS local audit orchestrator against the target project directory:

```powershell
powershell -ExecutionPolicy Bypass -File "<skill_dir>/scripts/run-audit.ps1" -TargetPath "<project_path>"
```

This automatically:
1. Detects frontend, backend, database, authentication, hosting, and applicable modular profiles (`static-web`, `react-node`, `firebase`, `supabase`, `gas`, `php-laravel`).
2. Executes built-in profile-aware static/configuration checks (`wsas-static-checks`).
3. Runs installed external scanners (`betterleaks`/`gitleaks`, `npm audit`, `composer audit`, `semgrep`) and honestly logs missing tools.
4. Produces redacted Markdown and JSON reports with Security Score and Release Gate status.

### Step 2 — Analyse (Contextual Threat Review)

Review the generated JSON/Markdown report AND inspect stack-specific trust boundaries using [checklist.md](./references/checklist.md):
- Identify assets, user roles, authentication boundaries, and public vs private endpoints.
- Distinguish false positives from real risks:
  - Example: A **Firebase web client `apiKey`** (`AIza...`) is public by design (`Info`), NOT a leaked secret — focus instead on `firestore.rules`, `storage.rules`, Custom Claims, and preventing `serviceAccountKey.json` exposure (`Critical`).
  - Example: A **Supabase `anon` key** is safe in browser code ONLY if PostgreSQL Row Level Security (RLS) is enabled and restrictive; a **`service_role` key** in client code is always `Critical`.
  - Example: **GitHub Pages** hosts only static frontend files; always audit the connected backend (Firebase, Supabase, GAS, API) separately.
- Classify every confirmed finding using [risk-rating.md](./references/risk-rating.md) (`Critical`, `High`, `Medium`, `Low`, `Info`).

### Step 3 — Fix (Human-Approved Minimal Patches)

For each confirmed finding (prioritizing `Critical` and `High` release blockers):
1. Explain the root cause and concrete exploit scenario.
2. Propose a **minimal, safe patch** (and credential rotation steps if any secret was exposed).
3. **Ask the user for explicit approval** before modifying application files, database rules, or CI workflows.

### Step 4 — Retest (Mandatory Proof)

After approved fixes are applied:
1. Re-run `run-audit.ps1` (and any stack-specific tests, e.g., Firebase Emulator rules tests, `npm test`, `php artisan test`).
2. Confirm that each targeted finding no longer appears in the fresh scanner output.

### Step 5 — Verify (Regression & Release Gate Check)

1. Confirm no new findings or regressions were introduced.
2. Check the final **Release Gate** (`PASS`, `WARN`, or `BLOCK`) and **Scanner Coverage**.
3. Deliver the final redacted Markdown & JSON audit reports (following [report-template.md](./references/report-template.md)).
4. Repeat Steps 1–5 until all release-blocking (`Critical` / `High`) issues are resolved and verified.
