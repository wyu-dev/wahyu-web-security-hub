#!/usr/bin/env python3
"""WSAS Security Audit Report Generator (Markdown + JSON).

Aggregates verified outputs from:
  - detect-stack.py
  - wsas-static-checks
  - Gitleaks / Betterleaks (JSON)
  - npm audit (JSON)
  - composer audit (JSON)
  - Semgrep (JSON)
  - OWASP ZAP baseline (JSON)

Enforces secret redaction, honest tool execution reporting, consistent severity rating,
Security Score (0-100), and Release Gate (PASS / WARN / BLOCK).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from redact import redact_obj, redact_text  # noqa: E402

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_RANK = {s: idx for idx, s in enumerate(SEVERITY_ORDER)}
SCORE_DEDUCTIONS = {
    "Critical": 25,
    "High": 15,
    "Medium": 7,
    "Low": 2,
    "Info": 0,
}


def normalize_severity(raw: str | None) -> str:
    if not raw:
        return "Info"
    low = str(raw).strip().lower()
    if low in {"critical", "crit", "error_critical"}:
        return "Critical"
    if low in {"high", "error"}:
        return "High"
    if low in {"medium", "moderate", "warning", "warn"}:
        return "Medium"
    if low in {"low"}:
        return "Low"
    return "Info"


def _load_json_optional(path: str | None) -> Any:
    if not path:
        return None
    p = Path(path)
    if not p.exists() or p.stat().st_size == 0:
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8-sig", errors="ignore"))
    except Exception:
        return None


def parse_gitleaks(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, list):
        return []
    findings: list[dict[str, Any]] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("RuleID") or item.get("rule") or "gitleaks-secret")
        file_path = str(item.get("File") or item.get("file") or "unknown")
        line = int(item.get("StartLine") or item.get("line") or 1)
        desc = str(item.get("Description") or f"Secret detected by rule {rule_id}")
        findings.append(
            {
                "tool": "gitleaks",
                "rule_id": rule_id,
                "title": desc,
                "severity": "Critical",
                "category": "Secrets Management",
                "file": file_path,
                "line": line,
                "cwe": "CWE-798",
                "evidence": f"Rule={rule_id} matched at {file_path}:{line} (value redacted)",
                "remediation": "Revoke/rotate the secret immediately, remove it from git history, and load via secure environment secrets.",
            }
        )
    return findings


def parse_npm_audit(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    findings: list[dict[str, Any]] = []
    vulns = data.get("vulnerabilities")
    if isinstance(vulns, dict):
        for pkg_name, info in vulns.items():
            if not isinstance(info, dict):
                continue
            sev = normalize_severity(info.get("severity"))
            via = info.get("via") or []
            advisory_titles: list[str] = []
            for entry in via:
                if isinstance(entry, dict) and entry.get("title"):
                    advisory_titles.append(str(entry["title"]))
            summary = "; ".join(advisory_titles[:2]) or f"Vulnerable npm package '{pkg_name}'"
            fix_available = info.get("fixAvailable")
            remed = "Run `npm audit fix` or upgrade the package to a patched version." if fix_available else "Upgrade or replace the vulnerable dependency; review advisory details."
            findings.append(
                {
                    "tool": "npm-audit",
                    "rule_id": f"NPM-{pkg_name}",
                    "title": f"Vulnerable dependency `{pkg_name}`: {summary}",
                    "severity": sev,
                    "category": "Dependency Vulnerability",
                    "file": "package-lock.json",
                    "line": 1,
                    "cwe": "CWE-1395",
                    "evidence": f"Package={pkg_name}, range={info.get('range', 'unknown')}, severity={sev}",
                    "remediation": remed,
                }
            )
    return findings


def parse_composer_audit(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    findings: list[dict[str, Any]] = []
    advisories = data.get("advisories")
    if isinstance(advisories, dict):
        for pkg, items in advisories.items():
            if not isinstance(items, list):
                continue
            for adv in items:
                if not isinstance(adv, dict):
                    continue
                sev = normalize_severity(adv.get("severity") or "high")
                cve = str(adv.get("cve") or adv.get("advisoryId") or "COMPOSER-ADV")
                findings.append(
                    {
                        "tool": "composer-audit",
                        "rule_id": cve,
                        "title": f"Vulnerable PHP package `{pkg}`: {adv.get('title', 'Security advisory')}",
                        "severity": sev,
                        "category": "Dependency Vulnerability",
                        "file": "composer.lock",
                        "line": 1,
                        "cwe": "CWE-1395",
                        "evidence": f"Package={pkg}, advisory={cve}, affected={adv.get('affectedVersions', 'unknown')}",
                        "remediation": f"Update `{pkg}` via `composer update {pkg}` to a non-vulnerable release.",
                    }
                )
    return findings


def parse_semgrep(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    findings: list[dict[str, Any]] = []
    for res in data.get("results") or []:
        if not isinstance(res, dict):
            continue
        extra = res.get("extra") or {}
        meta = extra.get("metadata") or {}
        sev = normalize_severity(extra.get("severity"))
        check_id = str(res.get("check_id") or "semgrep-rule")
        cwe_raw = meta.get("cwe")
        cwe = cwe_raw[0] if isinstance(cwe_raw, list) and cwe_raw else str(cwe_raw or "")
        findings.append(
            {
                "tool": "semgrep",
                "rule_id": check_id,
                "title": str(extra.get("message") or check_id)[:180],
                "severity": sev,
                "category": str(meta.get("category") or "Static Analysis (SAST)"),
                "file": str(res.get("path") or "unknown"),
                "line": int((res.get("start") or {}).get("line") or 1),
                "cwe": cwe,
                "evidence": redact_text(str(extra.get("lines") or f"{res.get('path')}:{(res.get('start') or {}).get('line', 1)}"))[:240],
                "remediation": str(extra.get("fix") or "Review Semgrep rule guidance and apply minimal secure patch."),
            }
        )
    return findings


def parse_zap(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    findings: list[dict[str, Any]] = []
    risk_map = {"3": "High", "2": "Medium", "1": "Low", "0": "Info"}
    for site in data.get("site") or []:
        if not isinstance(site, dict):
            continue
        site_name = str(site.get("@name") or "target")
        for alert in site.get("alerts") or []:
            if not isinstance(alert, dict):
                continue
            sev = risk_map.get(str(alert.get("riskcode", "0")), "Info")
            findings.append(
                {
                    "tool": "owasp-zap",
                    "rule_id": f"ZAP-{alert.get('pluginid', '0')}",
                    "title": str(alert.get("name") or "ZAP Alert"),
                    "severity": sev,
                    "category": "Dynamic Analysis (DAST)",
                    "file": site_name,
                    "line": 0,
                    "cwe": f"CWE-{alert.get('cweid')}" if alert.get("cweid") else "",
                    "evidence": f"URL={site_name}, instances={alert.get('count', '1')}, risk={alert.get('riskdesc', sev)}",
                    "remediation": str(alert.get("solution") or "Apply OWASP ZAP recommended hardening."),
                }
            )
    return findings


def evaluate_risk(findings: list[dict[str, Any]], tools_status: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        sev = normalize_severity(f.get("severity"))
        f["severity"] = sev
        counts[sev] += 1

    deduction = sum(counts[sev] * SCORE_DEDUCTIONS[sev] for sev in SEVERITY_ORDER)
    score = max(0, min(100, 100 - deduction))

    blocking_reasons: list[str] = []
    if counts["Critical"] > 0:
        blocking_reasons.append(f"{counts['Critical']} Critical finding(s) detected")
    if counts["High"] > 0:
        blocking_reasons.append(f"{counts['High']} High finding(s) detected")

    missing_tools = [t["name"] for t in tools_status if t.get("status") == "not_installed"]

    if blocking_reasons:
        release_gate = "BLOCK"
        gate_message = "Deployment BLOCKED — resolve all Critical and High findings and retest before release."
    elif counts["Medium"] > 0:
        release_gate = "WARN"
        gate_message = "Conditional PASS (WARN) — review and fix Medium findings before release."
    else:
        release_gate = "PASS"
        gate_message = "Release gate PASSED — no Critical, High, or Medium findings in executed checks."

    coverage = "COMPLETE" if not missing_tools else f"PARTIAL (missing: {', '.join(missing_tools)})"

    return {
        "counts": counts,
        "total_findings": len(findings),
        "security_score": score,
        "release_gate": release_gate,
        "gate_message": gate_message,
        "blocking_reasons": blocking_reasons,
        "scanner_coverage": coverage,
    }


def deduplicate_and_sort(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, int]] = set()
    unique: list[dict[str, Any]] = []
    for f in findings:
        key = (
            str(f.get("tool", "")),
            str(f.get("rule_id", "")),
            str(f.get("file", "")),
            int(f.get("line", 0)),
        )
        if key not in seen:
            seen.add(key)
            unique.append(redact_obj(f))
    unique.sort(key=lambda x: (SEVERITY_RANK.get(x["severity"], 99), x["file"], x["line"], x["rule_id"]))
    return unique


def build_report(
    stack_info: dict[str, Any],
    findings: list[dict[str, Any]],
    tools_status: list[dict[str, Any]],
    mode: str = "manual-local",
) -> dict[str, Any]:
    cleaned = deduplicate_and_sort(findings)
    risk = evaluate_risk(cleaned, tools_status)
    return redact_obj(
        {
            "schema_version": "1.0.0",
            "generated_at_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "audit_mode": mode,
            "project": {
                "name": stack_info.get("project_name", "unknown"),
                "target_path": stack_info.get("target_path", ""),
                "file_count": stack_info.get("file_count", 0),
                "detection": stack_info.get("detection", {}),
                "profiles": stack_info.get("profiles", []),
            },
            "summary": risk,
            "tools_executed": tools_status,
            "findings": cleaned,
        }
    )


def render_markdown(report: dict[str, Any]) -> str:
    proj = report["project"]
    det = proj.get("detection", {})
    summary = report["summary"]
    counts = summary["counts"]

    lines: list[str] = [
        f"# Web Security Audit Report — `{proj['name']}`",
        "",
        f"- **Generated (UTC):** `{report['generated_at_utc']}`",
        f"- **Audit Mode:** `{report['audit_mode']}`",
        f"- **Release Gate:** **`{summary['release_gate']}`**",
        f"- **Security Score:** `{summary['security_score']}/100` *(informational — a high score never overrides a Critical/High release block)*",
        f"- **Scanner Coverage:** `{summary['scanner_coverage']}`",
        "",
        f"> **Gate Decision:** {summary['gate_message']}",
        "",
        "## 1. Project Detection & Audit Profile",
        "",
        "| Dimension | Detected Value |",
        "| :--- | :--- |",
        f"| Frontend | {det.get('frontend', 'Unknown')} |",
        f"| Backend | {det.get('backend', 'Unknown')} |",
        f"| Database | {det.get('database', 'Unknown')} |",
        f"| Authentication | {det.get('authentication', 'Unknown')} |",
        f"| Hosting | {det.get('hosting', 'Unknown')} |",
        f"| Profiles Applied | `{', '.join(proj.get('profiles', []))}` |",
        f"| Files Inspected | {proj.get('file_count', 0)} |",
        "",
        "## 2. Severity Summary",
        "",
        "| Severity | Count | Policy Action |",
        "| :--- | :---: | :--- |",
        f"| **Critical** | {counts['Critical']} | Block deployment immediately |",
        f"| **High** | {counts['High']} | Block deployment |",
        f"| **Medium** | {counts['Medium']} | Fix before release |",
        f"| **Low** | {counts['Low']} | Track in backlog |",
        f"| **Info** | {counts['Info']} | Hardening recommendation |",
        f"| **Total** | **{summary['total_findings']}** | |",
        "",
        "## 3. Tool Execution Ledger (Honest Coverage)",
        "",
        "| Tool | Status | Notes |",
        "| :--- | :--- | :--- |",
    ]

    for t in report.get("tools_executed", []):
        lines.append(f"| `{t.get('name', 'unknown')}` | `{t.get('status', 'unknown')}` | {t.get('notes', '')} |")

    lines.extend(["", "## 4. Evidence-Backed Findings", ""])

    if not report["findings"]:
        lines.append("_No findings were reported by the executed scanners._")
    else:
        for idx, f in enumerate(report["findings"], start=1):
            loc = f"`{f['file']}:{f['line']}`" if f.get("line") else f"`{f['file']}`"
            cwe = f" ({f['cwe']})" if f.get("cwe") else ""
            lines.extend(
                [
                    f"### {idx}. [{f['severity']}] {f['title']}",
                    f"- **Rule / Tool:** `{f['rule_id']}` via `{f['tool']}`{cwe}",
                    f"- **Category:** {f['category']}",
                    f"- **Location:** {loc}",
                    f"- **Evidence (Redacted):** `{f['evidence']}`",
                    f"- **Recommended Remediation:** {f['remediation']}",
                    "",
                ]
            )

    lines.extend(
        [
            "## 5. Self-Refinement Verification Checklist",
            "",
            "- [ ] Confirm each finding against actual trust boundaries and business logic.",
            "- [ ] Obtain explicit human approval before applying patches or modifying database rules.",
            "- [ ] Apply minimal, targeted fixes without exposing secrets.",
            "- [ ] Re-run scanners (`Retest`) and attach fresh proof that findings are resolved.",
            "- [ ] Verify no regressions or new vulnerabilities were introduced (`Verify`).",
            "",
        ]
    )
    return "\n".join(lines)


def should_fail(report: dict[str, Any], fail_on: str) -> bool:
    counts = report["summary"]["counts"]
    level = fail_on.lower()
    if level == "none":
        return False
    if level == "critical":
        return counts["Critical"] > 0
    if level == "high":
        return counts["Critical"] > 0 or counts["High"] > 0
    if level == "medium":
        return counts["Critical"] > 0 or counts["High"] > 0 or counts["Medium"] > 0
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="WSAS Markdown + JSON Security Audit Report Generator")
    parser.add_argument("--stack", required=True, help="Path to stack detection JSON")
    parser.add_argument("--static", help="Path to wsas-static-checks JSON")
    parser.add_argument("--gitleaks", help="Path to Gitleaks/Betterleaks JSON")
    parser.add_argument("--npm-audit", help="Path to npm audit JSON")
    parser.add_argument("--composer-audit", help="Path to composer audit JSON")
    parser.add_argument("--semgrep", help="Path to Semgrep JSON")
    parser.add_argument("--zap", help="Path to OWASP ZAP JSON")
    parser.add_argument("--tools-status", help="Path to tool execution ledger JSON")
    parser.add_argument("--mode", default="manual-local", help="Audit mode label")
    parser.add_argument("--out-md", required=True, help="Output Markdown report path")
    parser.add_argument("--out-json", required=True, help="Output JSON report path")
    parser.add_argument("--fail-on", default="none", choices=["none", "critical", "high", "medium"])
    args = parser.parse_args()

    stack_info = _load_json_optional(args.stack) or {}
    tools_status = _load_json_optional(args.tools_status) or []

    all_findings: list[dict[str, Any]] = []
    static_data = _load_json_optional(args.static)
    if isinstance(static_data, dict):
        all_findings.extend(static_data.get("findings") or [])

    all_findings.extend(parse_gitleaks(_load_json_optional(args.gitleaks)))
    all_findings.extend(parse_npm_audit(_load_json_optional(args.npm_audit)))
    all_findings.extend(parse_composer_audit(_load_json_optional(args.composer_audit)))
    all_findings.extend(parse_semgrep(_load_json_optional(args.semgrep)))
    all_findings.extend(parse_zap(_load_json_optional(args.zap)))

    report = build_report(stack_info, all_findings, tools_status, mode=args.mode)

    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)

    out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")

    summary = report["summary"]
    print(
        f"WSAS Report Ready | Gate: {summary['release_gate']} | "
        f"Score: {summary['security_score']}/100 | "
        f"Findings: C={summary['counts']['Critical']} H={summary['counts']['High']} "
        f"M={summary['counts']['Medium']} L={summary['counts']['Low']} I={summary['counts']['Info']}"
    )
    print(f"Markdown : {out_md}")
    print(f"JSON     : {out_json}")

    return 2 if should_fail(report, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
