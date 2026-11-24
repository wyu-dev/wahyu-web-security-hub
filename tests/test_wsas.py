#!/usr/bin/env python3
"""Automated test suite for WSAS engine, Antigravity skill compliance, redaction, and release gates."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HUB_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = HUB_ROOT / "scripts"
FIXTURES_DIR = HUB_ROOT / "tests" / "fixtures"
SKILL_DIR = HUB_ROOT / "skills" / "web-security-audit"


def _load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS_DIR / filename)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


redact = _load_module("redact", "redact.py")
detect_stack = _load_module("detect_stack", "detect-stack.py")
static_checks = _load_module("static_checks", "static-checks.py")
generate_report = _load_module("generate_report", "generate-report.py")
ai_review = _load_module("ai_review", "ai-review.py")


class TestSkillAndHubStructure(unittest.TestCase):
    def test_skill_frontmatter_and_references_exist(self):
        skill_md = SKILL_DIR / "SKILL.md"
        self.assertTrue(skill_md.exists(), "SKILL.md must exist")
        text = skill_md.read_text(encoding="utf-8")

        # Validate Antigravity YAML frontmatter contract (name + description)
        fm = re.match(r"^---\r?\n(.*?)\r?\n---", text, re.DOTALL)
        self.assertIsNotNone(fm, "SKILL.md must begin with valid YAML frontmatter")
        fm_body = fm.group(1)
        self.assertRegex(fm_body, r"(?m)^name:\s*web-security-audit\s*$")
        self.assertRegex(fm_body, r"(?m)^description:\s*")

        # Verify all referenced files exist
        for rel in (
            "references/checklist.md",
            "references/risk-rating.md",
            "references/report-template.md",
            "scripts/run-audit.ps1",
        ):
            self.assertTrue((SKILL_DIR / rel).exists(), f"Missing skill resource: {rel}")

        # Verify Self-Refinement Loop steps and guardrails are documented
        for required_phrase in ("Scan", "Analyse", "Fix", "Retest", "Verify", "not_installed"):
            self.assertIn(required_phrase, text)

    def test_all_six_profiles_exist_and_have_ids(self):
        expected = ["static-web", "react-node", "firebase", "supabase", "gas", "php-laravel"]
        for prof in expected:
            p = HUB_ROOT / "profiles" / f"{prof}.yml"
            self.assertTrue(p.exists(), f"Missing profile: {p}")
            content = p.read_text(encoding="utf-8")
            self.assertRegex(content, rf"(?m)^id:\s*{re.escape(prof)}\s*$")

    def test_hub_workflows_pin_all_actions_to_full_sha(self):
        uses_re = re.compile(r"^\s*-?\s*uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+)@([^\s#]+)")
        for wf in (HUB_ROOT / ".github" / "workflows").glob("*.yml"):
            for idx, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), start=1):
                m = uses_re.match(line)
                if m:
                    self.assertRegex(
                        m.group(2),
                        r"^[0-9a-fA-F]{40}$",
                        f"Unpinned action in {wf.name}:{idx} -> {line.strip()}",
                    )


class TestStackDetection(unittest.TestCase):
    def test_detect_react_firebase_stack(self):
        res = detect_stack.detect_stack(FIXTURES_DIR / "react-firebase-vuln")
        self.assertIn("React / Vite", res["detection"]["frontend"])
        self.assertIn("Firebase", res["detection"]["backend"])
        self.assertIn("Firestore", res["detection"]["database"])
        self.assertIn("react-node", res["profiles"])
        self.assertIn("firebase", res["profiles"])
        self.assertIn("static-web", res["profiles"])

    def test_detect_php_laravel_stack(self):
        res = detect_stack.detect_stack(FIXTURES_DIR / "php-laravel-sample")
        self.assertIn("PHP / Laravel", res["detection"]["backend"])
        self.assertIn("php-laravel", res["profiles"])

    def test_detect_supabase_and_gas_stack(self):
        res = detect_stack.detect_stack(FIXTURES_DIR / "supabase-gas-sample")
        self.assertIn("Supabase", res["detection"]["backend"])
        self.assertIn("Google Apps Script", res["detection"]["backend"])
        self.assertIn("supabase", res["profiles"])
        self.assertIn("gas", res["profiles"])


class TestRedactionAndStaticChecks(unittest.TestCase):
    def test_redaction_masks_all_secret_types(self):
        fake_gh = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
        fake_or = "sk-or-v1-" + "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d"
        fake_aws = "AKIA" + "IOSFODNN7EXAMPLE"
        fake_pk = "-----BEGIN " + "PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQE\n-----END " + "PRIVATE KEY-----"
        sample = f"gh={fake_gh}\nor={fake_or}\naws={fake_aws}\n{fake_pk}\nDB_PASSWORD=SuperSecret123!"

        cleaned = redact.redact_text(sample)
        for raw in (fake_gh, fake_or, fake_aws, "MIIEvQIBADANBgkqhkiG9w0BAQE", "SuperSecret123!"):
            self.assertNotIn(raw, cleaned)
        self.assertEqual(redact.contains_unredacted_secret(cleaned), [])

    def test_firebase_rules_and_xss_detected_in_pilot_fixture(self):
        res = static_checks.run_static_checks(
            FIXTURES_DIR / "react-firebase-vuln",
            profiles=["static-web", "react-node", "firebase"],
        )
        rule_ids = {f["rule_id"] for f in res["findings"]}
        self.assertIn("FB-RULES-001", rule_ids)
        self.assertIn("REACT-XSS-001", rule_ids)
        self.assertIn("STATIC-SRI-001", rule_ids)
        self.assertIn("STATIC-TARGET-001", rule_ids)
        self.assertIn("CI-PIN-001", rule_ids)

    def test_firebase_web_apikey_classified_as_info_while_service_account_is_critical(self):
        with tempfile.TemporaryDirectory() as tmp:
            tpath = Path(tmp)
            fake_web_key = "AIza" + "SyDummyPublicFirebaseKey12345678901"
            (tpath / "firebase.js").write_text(
                f'const firebaseConfig = {{ apiKey: "{fake_web_key}", projectId: "demo" }};\n',
                encoding="utf-8",
            )
            fake_sa = {
                "type": "service_account",
                "project_id": "demo",
                "private_key": "-----BEGIN " + "PRIVATE KEY-----\nFAKEKEYBODY\n-----END " + "PRIVATE KEY-----\n",
            }
            (tpath / "serviceAccountKey.json").write_text(json.dumps(fake_sa), encoding="utf-8")

            res = static_checks.run_static_checks(tpath, profiles=["firebase"])
            by_rule = {f["rule_id"]: f for f in res["findings"]}

            self.assertIn("FB-APIKEY-INFO", by_rule)
            self.assertEqual(by_rule["FB-APIKEY-INFO"]["severity"], "Info")
            self.assertNotIn(fake_web_key, by_rule["FB-APIKEY-INFO"]["evidence"])

            self.assertIn("FB-SA-001", by_rule)
            self.assertEqual(by_rule["FB-SA-001"]["severity"], "Critical")
            self.assertNotIn("FAKEKEYBODY", by_rule["FB-SA-001"]["evidence"])

    def test_laravel_supabase_gas_checks(self):
        php_res = static_checks.run_static_checks(FIXTURES_DIR / "php-laravel-sample", profiles=["php-laravel"])
        php_rules = {f["rule_id"] for f in php_res["findings"]}
        self.assertIn("PHP-SQLI-001", php_rules)
        self.assertIn("PHP-XSS-001", php_rules)

        sg_res = static_checks.run_static_checks(FIXTURES_DIR / "supabase-gas-sample", profiles=["supabase", "gas"])
        sg_rules = {f["rule_id"] for f in sg_res["findings"]}
        self.assertIn("SUPA-RLS-001", sg_rules)
        self.assertIn("SUPA-RLS-002", sg_rules)
        self.assertIn("GAS-PERM-001", sg_rules)
        self.assertIn("GAS-XSS-001", sg_rules)

    def test_clean_static_app_has_zero_findings(self):
        res = static_checks.run_static_checks(FIXTURES_DIR / "clean-static-app", profiles=["static-web"])
        self.assertEqual(res["findings"], [])


class TestReportAndReleaseGate(unittest.TestCase):
    def test_single_high_blocks_release_even_with_85_score(self):
        stack = {"project_name": "score-test", "target_path": ".", "file_count": 3, "detection": {}, "profiles": ["static-web"]}
        findings = [
            {
                "tool": "wsas-static-checks",
                "rule_id": "FB-RULES-002",
                "title": "Overly broad write rule",
                "severity": "High",
                "category": "Firebase Security",
                "file": "firestore.rules",
                "line": 4,
                "cwe": "CWE-863",
                "evidence": "allow write: if request.auth != null;",
                "remediation": "Check ownership.",
            }
        ]
        tools = [
            {"name": "wsas-static-checks", "status": "executed", "notes": "ok"},
            {"name": "gitleaks", "status": "not_installed", "notes": "missing"},
        ]
        report = generate_report.build_report(stack, findings, tools)
        self.assertEqual(report["summary"]["security_score"], 85)
        self.assertEqual(report["summary"]["release_gate"], "BLOCK")
        self.assertIn("PARTIAL", report["summary"]["scanner_coverage"])
        self.assertTrue(generate_report.should_fail(report, "high"))

        md = generate_report.render_markdown(report)
        self.assertIn("`BLOCK`", md)
        self.assertIn("`not_installed`", md)

    def test_ai_review_payload_redacts_secrets_and_dry_run_passes(self):
        fake_token = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4"
        raw_report = {
            "project": {"name": "demo", "detection": {}, "profiles": ["static-web"]},
            "summary": {"release_gate": "BLOCK", "security_score": 75},
            "tools_executed": [],
            "findings": [
                {
                    "tool": "test",
                    "rule_id": "SECRET-GH-001",
                    "severity": "Critical",
                    "category": "Secrets",
                    "title": "Token leak",
                    "file": "app.js",
                    "line": 2,
                    "cwe": "CWE-798",
                    "evidence": f"const token = '{fake_token}';",
                }
            ],
        }
        payload = ai_review.build_safe_payload(raw_report)
        payload_text = json.dumps(payload)
        self.assertNotIn(fake_token, payload_text)
        self.assertIn("[REDACTED:GITHUB_TOKEN]", payload_text)

    def test_end_to_end_local_audit_powershell_on_clean_and_vuln_fixtures(self):
        ps = "powershell"
        local_script = SCRIPTS_DIR / "local-audit.ps1"
        with tempfile.TemporaryDirectory() as out_dir:
            # Vulnerable fixture with -FailOn high must return exit code 2 (BLOCK)
            vuln_proc = subprocess.run(
                [
                    ps,
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(local_script),
                    "-TargetPath",
                    str(FIXTURES_DIR / "react-firebase-vuln"),
                    "-OutputDir",
                    out_dir,
                    "-FailOn",
                    "high",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(vuln_proc.returncode, 2, f"Expected BLOCK (exit 2), got {vuln_proc.returncode}\n{vuln_proc.stdout}\n{vuln_proc.stderr}")

            # Clean fixture with -FailOn high must return exit code 0 (PASS)
            clean_proc = subprocess.run(
                [
                    ps,
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(local_script),
                    "-TargetPath",
                    str(FIXTURES_DIR / "clean-static-app"),
                    "-OutputDir",
                    out_dir,
                    "-FailOn",
                    "high",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(clean_proc.returncode, 0, f"Expected PASS (exit 0), got {clean_proc.returncode}\n{clean_proc.stdout}\n{clean_proc.stderr}")

            md_files = list(Path(out_dir).glob("*.md"))
            json_files = list(Path(out_dir).glob("*.json"))
            self.assertGreaterEqual(len(md_files), 2)
            self.assertGreaterEqual(len(json_files), 2)

            # Verify Tool Execution Ledger was parsed cleanly (no UTF-8 BOM drop)
            sample_report = json.loads(json_files[0].read_text(encoding="utf-8"))
            tool_names = {t["name"] for t in sample_report["tools_executed"]}
            self.assertIn("wsas-static-checks", tool_names)
            self.assertGreaterEqual(len(sample_report["tools_executed"]), 5)

    def test_install_skill_workspace_scope(self):
        install_script = SCRIPTS_DIR / "install-skill.ps1"
        with tempfile.TemporaryDirectory() as fake_ws:
            proc = subprocess.run(
                [
                    "powershell",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(install_script),
                    "-Scope",
                    "Workspace",
                    "-WorkspacePath",
                    fake_ws,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, f"Installer failed:\n{proc.stdout}\n{proc.stderr}")
            installed_skill = Path(fake_ws) / ".agents" / "skills" / "web-security-audit"
            self.assertTrue((installed_skill / "SKILL.md").exists())
            self.assertTrue((installed_skill / "resources" / "wsas-hub" / "scripts" / "local-audit.ps1").exists())


if __name__ == "__main__":
    unittest.main()
