#!/usr/bin/env python3
"""Built-in evidence-based static & configuration security scanner for WSAS.

Complements external tools (Gitleaks/Betterleaks, Semgrep, npm audit, composer audit,
CodeQL, OWASP ZAP) with profile-aware checks for Firebase, Supabase, Google Apps Script,
PHP/Laravel, React/Vite/Node, Static Web, and GitHub Actions workflows.

Every finding includes file path, line number, CWE, redacted evidence, and remediation.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from redact import redact_text  # noqa: E402

IGNORED_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".next",
    ".nuxt",
    ".vite",
    ".venv",
    "venv",
    "__pycache__",
    "wsas-output",
}

TEXT_EXTENSIONS = {
    ".html", ".htm", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue",
    ".css", ".json", ".yml", ".yaml", ".env", ".rules", ".sql", ".gs",
    ".php", ".blade.php", ".py", ".ps1", ".sh", ".toml", ".ini", ".xml", ".md",
}

CODE_EXTENSIONS = {
    ".html", ".htm", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue",
    ".gs", ".php",
}

PLACEHOLDER_VALUES = {
    "changeme", "change_me", "your_api_key", "your-api-key", "example",
    "placeholder", "replace_me", "dummy", "test", "null", "none", "false",
    "true", "redacted", "[redacted]", "xxxxxxxx",
}

SHA40_RE = re.compile(r"@[0-9a-fA-F]{40}\b")
USES_ACTION_RE = re.compile(r"^\s*-?\s*uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@([^\s#]+)")


def _make_finding(
    rule_id: str,
    title: str,
    severity: str,
    category: str,
    rel_file: str,
    line: int,
    evidence: str,
    remediation: str,
    cwe: str = "",
) -> dict[str, Any]:
    return {
        "tool": "wsas-static-checks",
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "category": category,
        "file": rel_file,
        "line": line,
        "cwe": cwe,
        "evidence": redact_text(evidence.strip())[:240],
        "remediation": remediation,
    }


def _iter_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fname in filenames:
            p = Path(dirpath) / fname
            if p.stat().st_size > 1_000_000:
                continue
            out.append(p)
    return out


def _is_env_example(name: str) -> bool:
    low = name.lower()
    return low.endswith((".example", ".sample", ".template", ".dist"))


def _scan_secrets(rel_path: str, path: Path, lines: list[str], findings: list[dict[str, Any]]) -> None:
    name_low = path.name.lower()
    if name_low.endswith((".md", ".txt")):
        # Avoid noisy docs false positives unless a literal private key block or live token appears.
        pass

    # Committed .env file check
    if (name_low == ".env" or name_low.startswith(".env.")) and not _is_env_example(name_low):
        findings.append(
            _make_finding(
                "SECRET-ENV-001",
                "Environment file (.env) present in project directory",
                "High",
                "Secrets Management",
                rel_path,
                1,
                f"File present: {rel_path}",
                "Add .env* to .gitignore, keep only .env.example with placeholders, and rotate any exposed credentials.",
                "CWE-798",
            )
        )

    full_text = "\n".join(lines)

    # Firebase Admin Service Account JSON
    if '"type"' in full_text and '"service_account"' in full_text and '"private_key"' in full_text:
        line_no = next((i + 1 for i, l in enumerate(lines) if "private_key" in l), 1)
        findings.append(
            _make_finding(
                "FB-SA-001",
                "Firebase / Google Cloud Service Account private key JSON detected",
                "Critical",
                "Secrets Management",
                rel_path,
                line_no,
                lines[line_no - 1],
                "Immediately revoke this service account key in Google Cloud / Firebase Console, purge it from git history, and load credentials only via secret manager.",
                "CWE-798",
            )
        )

    high_conf_patterns = [
        ("SECRET-PK-001", "Private key material detected in repository", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"), "Critical"),
        ("SECRET-GH-001", "GitHub personal/OAuth access token detected", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "Critical"),
        ("SECRET-AWS-001", "AWS Access Key ID detected", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "Critical"),
        ("SECRET-API-001", "OpenRouter / OpenAI / Stripe secret API key detected", re.compile(r"\bsk-(?:or-v1-|proj-|live-)[A-Za-z0-9_-]{20,}\b|\bsk_live_[A-Za-z0-9]{16,}\b"), "Critical"),
        ("SECRET-SLACK-001", "Slack token detected", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Critical"),
    ]

    for idx, line in enumerate(lines, start=1):
        # Skip test/documentation placeholder strings containing [REDACTED]
        if "[REDACTED" in line:
            continue

        for rule_id, title, pat, sev in high_conf_patterns:
            if pat.search(line):
                findings.append(
                    _make_finding(
                        rule_id,
                        title,
                        sev,
                        "Secrets Management",
                        rel_path,
                        idx,
                        line,
                        "Remove the credential from source control, rotate/revoke it immediately, and move it to environment secrets.",
                        "CWE-798",
                    )
                )

        # Supabase service_role exposure
        if re.search(r"(?i)(?:VITE_|NEXT_PUBLIC_)[A-Z0-9_]*SERVICE_ROLE", line) or (
            re.search(r"(?i)supabase.*service_role|service_role_key", line)
            and path.suffix.lower() in CODE_EXTENSIONS
            and not _is_env_example(name_low)
        ):
            findings.append(
                _make_finding(
                    "SUPA-KEY-001",
                    "Supabase service_role key referenced in client-exposed code or public env var",
                    "Critical",
                    "Supabase Security",
                    rel_path,
                    idx,
                    line,
                    "Never expose SUPABASE_SERVICE_ROLE_KEY in frontend code or VITE_/NEXT_PUBLIC_ variables. Use only server-side or Edge Functions.",
                    "CWE-798",
                )
            )

        # Distinguish Firebase public web API key (AIza...) -> Info, NOT Critical!
        if re.search(r"\bAIza[0-9A-Za-z_-]{35,45}\b", line):
            is_firebase_ctx = (
                "firebase" in full_text.lower()
                or "apikey" in line.lower()
                or "firebaseconfig" in full_text.lower()
            )
            if is_firebase_ctx:
                findings.append(
                    _make_finding(
                        "FB-APIKEY-INFO",
                        "Firebase web client API key found (public by design — verify Security Rules & HTTP referrer restrictions)",
                        "Info",
                        "Firebase Security",
                        rel_path,
                        idx,
                        line,
                        "Firebase web API keys are not secret on their own, but restrict the key by HTTP referrer/APIs in Google Cloud Console and enforce strict Firestore/Storage Security Rules.",
                        "CWE-200",
                    )
                )
            else:
                findings.append(
                    _make_finding(
                        "SECRET-GAPI-001",
                        "Google API key detected — verify scope and referrer restrictions",
                        "Medium",
                        "Secrets Management",
                        rel_path,
                        idx,
                        line,
                        "Move server-side Google API keys to environment variables and apply API/referrer restrictions in Google Cloud Console.",
                        "CWE-798",
                    )
                )


def _scan_firebase(rel_path: str, path: Path, lines: list[str], findings: list[dict[str, Any]]) -> None:
    name_low = path.name.lower()
    if name_low in {"firestore.rules", "storage.rules"}:
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//"):
                continue
            if re.search(r"allow\s+[^;]*\bwrite\b[^;]*:\s*if\s+true\b", stripped) or re.search(
                r"allow\s+read\s*,\s*write\s*:\s*if\s+true\b", stripped
            ):
                findings.append(
                    _make_finding(
                        "FB-RULES-001",
                        f"Unrestricted public write access in {path.name} (allow ...: if true)",
                        "Critical",
                        "Firebase Security",
                        rel_path,
                        idx,
                        line,
                        "Replace `if true` with least-privilege authentication, ownership (`request.auth.uid == userId`), role checks, and schema validation.",
                        "CWE-284",
                    )
                )
            elif re.search(r"allow\s+read\s*:\s*if\s+true\b", stripped):
                findings.append(
                    _make_finding(
                        "FB-RULES-003",
                        f"Public read rule in {path.name} (allow read: if true)",
                        "Medium",
                        "Firebase Security",
                        rel_path,
                        idx,
                        line,
                        "Verify this collection/path contains strictly public non-PII data; otherwise restrict read access to authenticated/authorized users.",
                        "CWE-284",
                    )
                )
            elif re.search(r"allow\s+[^;]*(?:write|update|delete|create)[^;]*:\s*if\s+request\.auth\s*!=\s*null\s*;", stripped):
                findings.append(
                    _make_finding(
                        "FB-RULES-002",
                        f"Broad write rule in {path.name} checks only request.auth != null without ownership/role verification",
                        "High",
                        "Firebase Security",
                        rel_path,
                        idx,
                        line,
                        "Enforce document ownership (`request.auth.uid == resource.data.ownerId`) or Custom Claims role checks in addition to `request.auth != null`.",
                        "CWE-863",
                    )
                )

    if name_low == "database.rules.json":
        for idx, line in enumerate(lines, start=1):
            if re.search(r'"\.(?:read|write)"\s*:\s*(?:true|"true")', line):
                findings.append(
                    _make_finding(
                        "FB-RTDB-001",
                        "Open Firebase Realtime Database rule (.read/.write set to true)",
                        "Critical",
                        "Firebase Security",
                        rel_path,
                        idx,
                        line,
                        "Restrict Realtime Database rules using `auth != null` and path-level user/role authorization.",
                        "CWE-284",
                    )
                )


def _scan_supabase(rel_path: str, path: Path, lines: list[str], findings: list[dict[str, Any]]) -> None:
    if path.suffix.lower() != ".sql":
        return
    full_text = "\n".join(lines)
    # Find CREATE TABLE statements and verify ENABLE ROW LEVEL SECURITY
    for idx, line in enumerate(lines, start=1):
        m = re.search(r"(?i)create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?\"?([A-Za-z0-9_]+)\"?", line)
        if m:
            table = m.group(1)
            rls_pat = re.compile(
                rf"(?i)alter\s+table\s+(?:only\s+)?(?:public\.)?\"?{re.escape(table)}\"?\s+enable\s+row\s+level\s+security"
            )
            if not rls_pat.search(full_text):
                findings.append(
                    _make_finding(
                        "SUPA-RLS-001",
                        f"Table '{table}' created without ENABLE ROW LEVEL SECURITY in migration",
                        "High",
                        "Supabase Security",
                        rel_path,
                        idx,
                        line,
                        f"Add `ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY;` and define explicit least-privilege policies.",
                        "CWE-284",
                    )
                )

        if re.search(r"(?i)(?:using|with\s+check)\s*\(\s*true\s*\)", line):
            findings.append(
                _make_finding(
                    "SUPA-RLS-002",
                    "Permissive Supabase RLS policy using (true) condition",
                    "High",
                    "Supabase Security",
                    rel_path,
                    idx,
                    line,
                    "Replace `USING (true)` / `WITH CHECK (true)` on sensitive or write policies with `auth.uid() = user_id` or role checks.",
                    "CWE-863",
                )
            )


def _scan_gas(rel_path: str, path: Path, lines: list[str], findings: list[dict[str, Any]]) -> None:
    name_low = path.name.lower()
    if name_low == "appsscript.json":
        full = "\n".join(lines)
        if '"USER_DEPLOYING"' in full and '"ANYONE_ANONYMOUS"' in full:
            line_no = next((i + 1 for i, l in enumerate(lines) if "ANYONE_ANONYMOUS" in l), 1)
            findings.append(
                _make_finding(
                    "GAS-PERM-001",
                    "Google Apps Script Web App executes as USER_DEPLOYING with ANYONE_ANONYMOUS access",
                    "High",
                    "Google Apps Script Security",
                    rel_path,
                    line_no,
                    lines[line_no - 1],
                    "Restrict `webapp.access` to MYSELF or DOMAIN, or enforce strong server-side token/authorization validation and minimal OAuth scopes.",
                    "CWE-250",
                )
            )
    if path.suffix.lower() in {".html", ".htm"}:
        for idx, line in enumerate(lines, start=1):
            if "<?!=" in line:
                findings.append(
                    _make_finding(
                        "GAS-XSS-001",
                        "Unescaped Google Apps Script force-printing scriptlet (<?!= ... ?>)",
                        "Medium",
                        "Google Apps Script Security",
                        rel_path,
                        idx,
                        line,
                        "Use contextual auto-escaping scriptlets `<?= ... ?>` unless rendering strictly trusted static HTML partials.",
                        "CWE-79",
                    )
                )


def _scan_php_laravel(rel_path: str, path: Path, lines: list[str], findings: list[dict[str, Any]]) -> None:
    name_low = path.name.lower()
    if (name_low == ".env" or name_low.startswith(".env.")) and not _is_env_example(name_low):
        for idx, line in enumerate(lines, start=1):
            if re.match(r"^\s*APP_DEBUG\s*=\s*true\b", line, re.IGNORECASE):
                findings.append(
                    _make_finding(
                        "PHP-DEBUG-001",
                        "Laravel APP_DEBUG=true enabled",
                        "High",
                        "PHP / Laravel Security",
                        rel_path,
                        idx,
                        line,
                        "Set `APP_DEBUG=false` in staging/production to prevent stack trace and environment secret disclosure.",
                        "CWE-215",
                    )
                )

    if name_low.endswith(".blade.php"):
        for idx, line in enumerate(lines, start=1):
            if "{!!" in line and "!!}" in line:
                findings.append(
                    _make_finding(
                        "PHP-XSS-001",
                        "Unescaped Blade output ({!! ... !!}) may allow XSS",
                        "Medium",
                        "PHP / Laravel Security",
                        rel_path,
                        idx,
                        line,
                        "Use escaped Blade syntax `{{ ... }}` or sanitize HTML through HTMLPurifier before rendering.",
                        "CWE-79",
                    )
                )

    if path.suffix.lower() == ".php":
        for idx, line in enumerate(lines, start=1):
            if re.search(r"(?:DB::raw|whereRaw|selectRaw|orderByRaw)\s*\([^)]*\$", line):
                findings.append(
                    _make_finding(
                        "PHP-SQLI-001",
                        "Potential SQL injection via variable interpolation in raw Laravel query",
                        "High",
                        "PHP / Laravel Security",
                        rel_path,
                        idx,
                        line,
                        "Use parameter bindings (e.g., `whereRaw('email = ?', [$email])`) or Eloquent query builder methods.",
                        "CWE-89",
                    )
                )
            if re.search(r"\$guarded\s*=\s*\[\s*\]", line):
                findings.append(
                    _make_finding(
                        "PHP-MASS-001",
                        "Eloquent model disables mass-assignment protection ($guarded = [])",
                        "Medium",
                        "PHP / Laravel Security",
                        rel_path,
                        idx,
                        line,
                        "Define an explicit `$fillable` allowlist and pass validated request fields (`$request->validated()`).",
                        "CWE-915",
                    )
                )
            if re.search(r"\becho\s+\$_(?:GET|POST|REQUEST|COOKIE)\b", line):
                findings.append(
                    _make_finding(
                        "PHP-XSS-002",
                        "Direct unescaped echo of PHP superglobal user input",
                        "High",
                        "PHP / Laravel Security",
                        rel_path,
                        idx,
                        line,
                        "Escape output using `htmlspecialchars($val, ENT_QUOTES, 'UTF-8')`.",
                        "CWE-79",
                    )
                )


def _scan_web_js(rel_path: str, path: Path, lines: list[str], findings: list[dict[str, Any]]) -> None:
    ext = path.suffix.lower()
    if ext in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".html", ".htm"}:
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith(("//", "/*", "*")):
                continue
            if re.search(r"\.(?:innerHTML|outerHTML)\s*=|document\.write\s*\(", line) and "dompurify" not in line.lower():
                findings.append(
                    _make_finding(
                        "WEB-XSS-001",
                        "Unsafe DOM HTML sink (innerHTML / outerHTML / document.write) without visible sanitization",
                        "Medium",
                        "Cross-Site Scripting (XSS)",
                        rel_path,
                        idx,
                        line,
                        "Use `textContent` / safe DOM APIs or sanitize untrusted HTML with DOMPurify before insertion.",
                        "CWE-79",
                    )
                )
            if "dangerouslySetInnerHTML" in line and "dompurify" not in line.lower():
                findings.append(
                    _make_finding(
                        "REACT-XSS-001",
                        "React dangerouslySetInnerHTML used without visible DOMPurify sanitization",
                        "Medium",
                        "Cross-Site Scripting (XSS)",
                        rel_path,
                        idx,
                        line,
                        "Avoid `dangerouslySetInnerHTML` or sanitize content strictly via `DOMPurify.sanitize(...)`.",
                        "CWE-79",
                    )
                )
            if re.search(r"\beval\s*\(|\bnew\s+Function\s*\(", line):
                findings.append(
                    _make_finding(
                        "WEB-EVAL-001",
                        "Dynamic code execution via eval() or new Function()",
                        "High",
                        "Code Injection",
                        rel_path,
                        idx,
                        line,
                        "Remove `eval()` / `new Function()` and replace with structured parsing (e.g., `JSON.parse`).",
                        "CWE-95",
                    )
                )

    if ext in {".html", ".htm"}:
        for idx, line in enumerate(lines, start=1):
            if re.search(r"<script[^>]+src=[\"']https?://", line, re.IGNORECASE) and "integrity=" not in line.lower():
                findings.append(
                    _make_finding(
                        "STATIC-SRI-001",
                        "External CDN script loaded without Subresource Integrity (integrity attribute)",
                        "Low",
                        "Supply Chain Security",
                        rel_path,
                        idx,
                        line,
                        "Add `integrity=\"sha384-...\" crossorigin=\"anonymous\"` or bundle the dependency locally.",
                        "CWE-353",
                    )
                )
            if 'target="_blank"' in line.lower() and "noopener" not in line.lower():
                findings.append(
                    _make_finding(
                        "STATIC-TARGET-001",
                        "Link opens new tab (target=\"_blank\") without rel=\"noopener noreferrer\"",
                        "Low",
                        "Browser Security",
                        rel_path,
                        idx,
                        line,
                        "Add `rel=\"noopener noreferrer\"` to external links using `target=\"_blank\"`.",
                        "CWE-1022",
                    )
                )


def _scan_github_actions(rel_path: str, lines: list[str], findings: list[dict[str, Any]]) -> None:
    if not rel_path.lower().startswith(".github/workflows/"):
        return
    for idx, line in enumerate(lines, start=1):
        m = USES_ACTION_RE.match(line)
        if not m:
            continue
        ref = m.group(2)
        if not re.fullmatch(r"[0-9a-fA-F]{40}", ref):
            findings.append(
                _make_finding(
                    "CI-PIN-001",
                    f"GitHub Action '{m.group(1)}' is pinned to mutable ref '@{ref}' instead of a 40-char commit SHA",
                    "Low",
                    "CI/CD Supply Chain",
                    rel_path,
                    idx,
                    line,
                    "Pin third-party GitHub Actions and reusable workflows to verified full 40-character commit SHAs with a version comment.",
                    "CWE-829",
                )
            )


def run_static_checks(target_dir: str | Path, profiles: list[str] | None = None) -> dict[str, Any]:
    root = Path(target_dir).resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"Target directory not found: {root}")

    active_profiles = set(profiles or ["static-web", "react-node", "firebase", "supabase", "gas", "php-laravel"])
    findings: list[dict[str, Any]] = []
    scanned_files = 0

    for path in _iter_files(root):
        rel_path = path.relative_to(root).as_posix()
        name_low = path.name.lower()
        ext = path.suffix.lower()

        is_candidate = (
            ext in TEXT_EXTENSIONS
            or name_low.startswith(".env")
            or name_low in {"firestore.rules", "storage.rules", "database.rules.json", "appsscript.json"}
        )
        if not is_candidate:
            continue

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        scanned_files += 1
        lines = content.splitlines()

        _scan_secrets(rel_path, path, lines, findings)
        _scan_github_actions(rel_path, lines, findings)

        if "firebase" in active_profiles:
            _scan_firebase(rel_path, path, lines, findings)
        if "supabase" in active_profiles:
            _scan_supabase(rel_path, path, lines, findings)
        if "gas" in active_profiles:
            _scan_gas(rel_path, path, lines, findings)
        if "php-laravel" in active_profiles:
            _scan_php_laravel(rel_path, path, lines, findings)
        if active_profiles & {"static-web", "react-node", "firebase", "supabase"}:
            _scan_web_js(rel_path, path, lines, findings)

    return {
        "tool": "wsas-static-checks",
        "status": "executed",
        "scanned_files": scanned_files,
        "profiles_applied": sorted(active_profiles),
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="WSAS built-in static & configuration security checks")
    parser.add_argument("target", help="Path to target project directory")
    parser.add_argument("--profiles", help="Comma-separated profile IDs (optional)")
    parser.add_argument("--output", help="Write JSON output to file")
    args = parser.parse_args()

    profs = [p.strip() for p in args.profiles.split(",") if p.strip()] if args.profiles else None
    result = run_static_checks(args.target, profiles=profs)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    else:
        print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
