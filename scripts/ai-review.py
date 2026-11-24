#!/usr/bin/env python3
"""Optional OpenRouter AI Security Reviewer for WSAS.

STRICT SECURITY GUARANTEE:
  - Never sends raw files, .env files, or unredacted credentials to OpenRouter.
  - Only sends redacted structured summaries from a generated WSAS JSON report.
  - Fails closed if any high-confidence unredacted secret pattern is detected in payload.
  - Completely optional: requires explicit invocation + OPENROUTER_API_KEY env var.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from redact import contains_unredacted_secret, redact_obj  # noqa: E402

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "google/gemini-2.5-flash"


def build_safe_payload(report: dict[str, Any], model: str = DEFAULT_MODEL) -> dict[str, Any]:
    """Build a strictly redacted OpenRouter request payload from a WSAS JSON report."""
    safe_report = redact_obj(
        {
            "project": {
                "name": report.get("project", {}).get("name", "unknown"),
                "detection": report.get("project", {}).get("detection", {}),
                "profiles": report.get("project", {}).get("profiles", []),
            },
            "summary": report.get("summary", {}),
            "tools_executed": report.get("tools_executed", []),
            "findings": [
                {
                    "tool": f.get("tool"),
                    "rule_id": f.get("rule_id"),
                    "severity": f.get("severity"),
                    "category": f.get("category"),
                    "title": f.get("title"),
                    "file": f.get("file"),
                    "line": f.get("line"),
                    "cwe": f.get("cwe"),
                    "evidence": f.get("evidence"),
                }
                for f in (report.get("findings") or [])[:50]
            ],
        }
    )

    serialized = json.dumps(safe_report, indent=2)
    leaked = contains_unredacted_secret(serialized)
    if leaked:
        raise ValueError(
            f"Refusing to send payload to OpenRouter: unredacted secret pattern(s) detected: {', '.join(leaked)}"
        )

    system_prompt = (
        "You are a senior application security engineer reviewing automated WSAS scan findings. "
        "Base every statement strictly on the provided evidence. Never invent findings or claim "
        "scanners ran if their status is not_installed. Prioritize release-blocking (Critical/High) "
        "issues, explain real-world exploit risk in context of the detected stack, propose minimal "
        "safe patches, and specify exact retest commands."
    )
    user_prompt = (
        "Analyze the following redacted WSAS security audit JSON and produce a concise Markdown "
        "remediation plan grouped by priority (Release Blockers -> Pre-Release -> Hardening):\n\n"
        f"```json\n{serialized}\n```"
    )

    return {
        "model": model,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
    }


def call_openrouter(payload: dict[str, Any], api_key: str, timeout: int = 45) -> str:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OPENROUTER_URL,
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/wyu-dev/wahyu-web-security-hub",
            "X-Title": "WSAS Security Audit Reviewer",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError("OpenRouter returned an empty choices array.")
    return str(choices[0].get("message", {}).get("content", "")).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Optional OpenRouter AI reviewer for redacted WSAS reports")
    parser.add_argument("--report-json", required=True, help="Path to generated WSAS JSON report")
    parser.add_argument("--model", default=os.environ.get("OPENROUTER_MODEL", DEFAULT_MODEL))
    parser.add_argument("--output", help="Optional Markdown file path to save AI review")
    parser.add_argument("--dry-run", action="store_true", help="Validate redaction and print payload without network call")
    args = parser.parse_args()

    report_path = Path(args.report_json)
    if not report_path.exists():
        print(f"ERROR: Report file not found: {report_path}", file=sys.stderr)
        return 1

    report = json.loads(report_path.read_text(encoding="utf-8"))
    try:
        payload = build_safe_payload(report, model=args.model)
    except ValueError as exc:
        print(f"SECURITY BLOCK: {exc}", file=sys.stderr)
        return 2

    if args.dry_run:
        print("DRY-RUN OK: Payload passed strict secret-redaction check.")
        print(json.dumps({"model": payload["model"], "finding_count": len(report.get("findings") or [])}, indent=2))
        return 0

    api_key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not api_key:
        print("INFO: OPENROUTER_API_KEY is not set. Skipping optional AI review.", file=sys.stderr)
        return 0

    try:
        markdown = call_openrouter(payload, api_key=api_key)
    except (urllib.error.URLError, TimeoutError, RuntimeError) as exc:
        print(f"ERROR: OpenRouter request failed: {exc}", file=sys.stderr)
        return 1

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(markdown + "\n", encoding="utf-8")
        print(f"AI review saved to: {out}")
    else:
        print(markdown)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
