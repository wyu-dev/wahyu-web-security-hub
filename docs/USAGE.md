# WSAS Practical Usage Guide

## Mode A — Manual Local Audit (Antigravity IDE)

### Option 1: Ask Antigravity directly (using the `web-security-audit` skill)

Once installed, open any project in Antigravity IDE and prompt:
- `"Run a web security audit on this project using web-security-audit"`
- `"Jalankan audit keselamatan WSAS pada projek ini sebelum deploy"`

Antigravity will follow the **Security Self-Refinement Loop**:
1. **Scan** — Detect stack & run available scanners.
2. **Analyse** — Verify findings against stack trust boundaries (e.g., Firestore rules, Supabase RLS, GAS permissions, Laravel SQL/Blade).
3. **Fix** — Propose minimal patches and wait for your explicit approval before editing code or database rules.
4. **Retest** — Re-run scanners after approved patches.
5. **Verify** — Confirm zero regressions and final Release Gate status.

### Option 2: Run directly from PowerShell

```powershell
# Audit any local project folder
.\scripts\local-audit.ps1 -TargetPath "C:\Users\wahyu\Documents\Coding\my-react-firebase-app"

# Enforce a strict local release gate (exits with code 2 if High/Critical found)
.\scripts\local-audit.ps1 -TargetPath "C:\Users\wahyu\Documents\Coding\my-project" -FailOn high

# Save reports to a custom directory
.\scripts\local-audit.ps1 -TargetPath "C:\Users\wahyu\Documents\Coding\my-project" -OutputDir ".\reports\pilot"
```

Outputs generated:
- `<project>-audit-<timestamp>.md` (human-readable report)
- `<project>-audit-<timestamp>.json` (machine-readable archive for tracking history)

### Inspect Stack Detection Only

```powershell
python .\scripts\detect-stack.py "C:\path\to\project"
```

## Mode B — Automated CI/CD Audit (GitHub Actions)

Every push to `main`, every Pull Request, and every Monday at `02:00 UTC`, `.github/workflows/security-audit.yml` in a connected project triggers `reusable-audit.yml`:
1. **Secret Detection** (`gitleaks-action@v3`, SHA-pinned)
2. **Dependency Audit** (`npm audit` / `composer audit` if lockfiles exist)
3. **SAST** (Semgrep Community Edition; optional CodeQL for public/Code-Security repos)
4. **WSAS Stack Audit & Release Gate** (auto-detects stack, runs profile rules, posts Markdown report to GitHub Job Summary, uploads MD+JSON artifacts, blocks PR/merge on Critical/High)
5. **Optional Passive DAST** (OWASP ZAP Baseline — runs ONLY when manually enabled with an authorized `staging_url`, never active scan on production)

## Definition of Done (Secure-by-Design Habit)

Before releasing any project (Portal LI, Sistem SPPA, Bintang Bijak, Sistem Aduan, Aplikasi Matematik):
- [ ] Local WSAS audit executed and reviewed.
- [ ] Release Gate is **`PASS`** (zero open `Critical` or `High` issues).
- [ ] Firebase Security Rules / Supabase RLS / GAS permissions verified separately from GitHub Pages frontend.
- [ ] GitHub Actions `security-audit.yml` green on PR and `main`.
- [ ] Redacted Markdown + JSON report archived for baseline comparison.
