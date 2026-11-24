# WSAS Report Schema & Redaction Standard

Every WSAS audit produces two synchronized artifacts:
1. **Markdown Report** (`<project>-audit-<timestamp>.md`) — for human review, PR comments, and audit history.
2. **JSON Report** (`<project>-audit-<timestamp>.json`) — machine-readable archive for trend tracking, dashboards (Phase 5), and CI release gates.

## Mandatory Redaction Policy

Before any finding is printed, written to disk, or sent to an optional AI reviewer:
- All private keys (`-----BEGIN ... PRIVATE KEY-----`), GitHub tokens, AWS keys, OpenRouter/OpenAI/Stripe keys, Slack tokens, JWTs, database connection passwords, Bearer tokens, and `key=value` secret assignments MUST be replaced with `[REDACTED:...]`.
- Raw `.env` contents or service account JSON payloads MUST NEVER be copied into reports or AI prompts.

## JSON Schema (v1.0.0)

```json
{
  "schema_version": "1.0.0",
  "generated_at_utc": "2026-11-24T13:00:00Z",
  "audit_mode": "manual-local | github-actions",
  "project": {
    "name": "my-project",
    "target_path": "...",
    "file_count": 42,
    "detection": {
      "frontend": "React / Vite",
      "backend": "Firebase",
      "database": "Firestore",
      "authentication": "Firebase Auth",
      "hosting": "GitHub Pages / Static Hosting"
    },
    "profiles": ["static-web", "react-node", "firebase"]
  },
  "summary": {
    "counts": { "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0 },
    "total_findings": 0,
    "security_score": 100,
    "release_gate": "PASS | WARN | BLOCK",
    "gate_message": "...",
    "blocking_reasons": [],
    "scanner_coverage": "COMPLETE | PARTIAL (missing: ...)"
  },
  "tools_executed": [
    { "name": "wsas-static-checks", "status": "executed", "notes": "..." }
  ],
  "findings": [
    {
      "tool": "wsas-static-checks",
      "rule_id": "FB-RULES-001",
      "title": "...",
      "severity": "Critical",
      "category": "Firebase Security",
      "file": "firestore.rules",
      "line": 5,
      "cwe": "CWE-284",
      "evidence": "allow read, write: if true;",
      "remediation": "..."
    }
  ]
}
```
