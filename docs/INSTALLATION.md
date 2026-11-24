# WSAS Installation Guide

This guide covers installing **Web Security Audit System (WSAS)** locally for **Antigravity IDE** and connecting it to **GitHub**.

## 1. Prerequisites

| Tool | Required? | Purpose | Install Command (Windows) |
| :--- | :--- | :--- | :--- |
| **Python 3.10+** | Required | Stack detection, static checks, redaction, report generator (zero pip dependencies) | Already installed / `winget install Python.Python.3.12` |
| **PowerShell 5.1+ / 7+** | Required (Windows) | Runs `local-audit.ps1` and `install-skill.ps1` | Built into Windows |
| **Git & GitHub CLI (`gh`)** | Recommended | Repo management & GitHub Actions setup | `winget install Git.Git GitHub.cli` |
| **Gitleaks** *(or Betterleaks)* | Strongly Recommended | Full git-history & entropy secret scanner | `winget install Gitleaks.Gitleaks` |
| **Node.js + npm** | If auditing JS/React | Runs `npm audit` | `winget install OpenJS.NodeJS.LTS` |
| **PHP + Composer** | If auditing PHP/Laravel | Runs `composer audit` | Herd / `composer` |
| **Semgrep** *(optional locally)* | Optional locally (runs in CI) | Multi-language SAST rules | Runs natively in GitHub Actions (Linux) or via WSL/Docker |

> **Honest Coverage Principle:** If Gitleaks or Semgrep is not installed locally, WSAS still runs `detect-stack.py`, `static-checks.py`, `npm audit`, and `composer audit`, and honestly marks missing scanners as `not_installed` in the report instead of faking a pass.

## 2. Install the `web-security-audit` Skill in Antigravity IDE

Antigravity discovers skills from two verified locations:
- **Global (recommended — works across ALL projects on your machine):** `~/.gemini/config/skills/web-security-audit/`
- **Workspace (project-specific, checked into VCS):** `<project>/.agents/skills/web-security-audit/`

Run the provided installer from `wahyu-web-security-hub`:

```powershell
# Install globally for every project opened in Antigravity IDE
powershell -ExecutionPolicy Bypass -File .\scripts\install-skill.ps1 -Scope Global

# Or install into one specific project workspace
powershell -ExecutionPolicy Bypass -File .\scripts\install-skill.ps1 -Scope Workspace -WorkspacePath "C:\path\to\your-project"
```

The installer copies `SKILL.md`, `references/`, `scripts/`, and bundles the WSAS hub engine into `resources/wsas-hub/` so the skill works standalone from any project folder, then validates the `SKILL.md` YAML frontmatter.

## 3. Publish `wahyu-web-security-hub` to GitHub (Phase 3 Setup)

When you are ready to share reusable workflows across repositories (Portal LI, Sistem SPPA, Bintang Bijak, Sistem Aduan, Aplikasi Matematik):

```powershell
cd "C:\Users\wahyu\Documents\Coding\web security\wahyu-web-security-hub"
git init -b main
git add .
git commit -m "feat: initialize WSAS Security Hub (Phase 1-3)"

# Create GitHub repository (public or private)
gh repo create wyu-dev/wahyu-web-security-hub --private --source=. --remote=origin --push

# Get the exact 40-char commit SHA to pin in caller repos
git rev-parse HEAD
```

> **Note on Private Reusable Workflows:** If `wahyu-web-security-hub` is a private repository under a personal account, GitHub only allows private reusable workflows to be called by the same repo (for cross-repo reuse across personal repos, make `wahyu-web-security-hub` **public** — it contains only generic security rules and zero project secrets — or host under a GitHub Organization with internal workflow sharing enabled).

## 4. Connect Any Other Project Repository

1. Copy `templates/caller-security-audit.yml` into `<target-repo>/.github/workflows/security-audit.yml`.
2. Replace `REPLACE_WITH_VERIFIED_COMMIT_SHA` with the 40-character commit SHA from `git rev-parse HEAD`.
3. Optionally copy `templates/SECURITY.md` and merge `templates/.gitignore` into the target repository.

## 5. Optional: Enable OpenRouter AI Reviewer

Basic scanning and reporting require **zero AI subscriptions**. To optionally run AI triage on redacted JSON reports:

```powershell
$env:OPENROUTER_API_KEY = "your-openrouter-key"
.\scripts\local-audit.ps1 -TargetPath "C:\path\to\project" -EnableAiReview
```

WSAS strictly redacts secrets and refuses (`exit 2`) to call OpenRouter if any raw secret pattern is detected in the outgoing payload.
