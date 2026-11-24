#!/usr/bin/env python3
"""Automatic technology stack and audit profile detector for WSAS.

Pure Python stdlib implementation — requires no external dependencies.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

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
    ".idea",
    ".vscode",
}

PROFILE_LABELS = {
    "static-web": "Static web & HTML/JS security",
    "react-node": "JavaScript / React / Node dependency & code security",
    "firebase": "Firebase security rules & authentication",
    "supabase": "Supabase RLS & API key boundaries",
    "gas": "Google Apps Script permissions & authorization",
    "php-laravel": "PHP / Laravel SQLi, XSS, CSRF & config security",
}


def _safe_read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _safe_read_text(path: Path, max_bytes: int = 65536) -> str:
    try:
        with path.open("rb") as f:
            return f.read(max_bytes).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def walk_project_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fname in filenames:
            files.append(Path(dirpath) / fname)
    return files


def detect_stack(target_dir: str | Path) -> dict[str, Any]:
    root = Path(target_dir).resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"Target directory not found: {root}")

    all_files = walk_project_files(root)
    rel_paths = [p.relative_to(root).as_posix() for p in all_files]
    rel_lower = {rp.lower(): rp for rp in rel_paths}
    basenames = {p.name.lower() for p in all_files}
    extensions = {p.suffix.lower() for p in all_files}

    package_json_path = root / "package.json"
    package_json = _safe_read_json(package_json_path) if package_json_path.exists() else {}
    npm_deps: set[str] = set()
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        sec = package_json.get(section)
        if isinstance(sec, dict):
            npm_deps.update(str(k).lower() for k in sec.keys())

    composer_json_path = root / "composer.json"
    composer_json = _safe_read_json(composer_json_path) if composer_json_path.exists() else {}
    composer_deps: set[str] = set()
    for section in ("require", "require-dev"):
        sec = composer_json.get(section)
        if isinstance(sec, dict):
            composer_deps.update(str(k).lower() for k in sec.keys())

    # Scan sample of JS/TS/HTML files for CDN imports of Firebase/Supabase if no package.json
    cdn_firebase = False
    cdn_supabase = False
    for p in all_files:
        if p.suffix.lower() in {".html", ".htm", ".js", ".mjs", ".ts", ".tsx", ".jsx"}:
            txt = _safe_read_text(p, max_bytes=32768)
            if "firebase" in txt.lower() and ("gstatic.com/firebasejs" in txt.lower() or "initializeapp" in txt.lower()):
                cdn_firebase = True
            if "supabase" in txt.lower() and ("createclient" in txt.lower() or "supabase.co" in txt.lower()):
                cdn_supabase = True

    # Detect technologies
    has_html = ".html" in extensions or ".htm" in extensions
    has_react = "react" in npm_deps or ".jsx" in extensions or ".tsx" in extensions
    has_vite = "vite" in npm_deps or any(n.startswith("vite.config.") for n in basenames)
    has_nextjs = "next" in npm_deps or any(n.startswith("next.config.") for n in basenames)
    has_vue = "vue" in npm_deps or ".vue" in extensions
    has_express_or_node_api = bool(npm_deps & {"express", "fastify", "koa", "hono", "@nestjs/core"})
    has_node = package_json_path.exists()

    has_firebase = (
        bool({"firebase.json", "firestore.rules", "storage.rules", "database.rules.json", ".firebaserc"} & basenames)
        or bool(npm_deps & {"firebase", "firebase-admin", "firebase-functions"})
        or cdn_firebase
    )
    has_firestore = "firestore.rules" in basenames or (
        (root / "firebase.json").exists() and "firestore" in _safe_read_text(root / "firebase.json").lower()
    )
    has_rtdb = "database.rules.json" in basenames

    has_supabase = (
        "supabase/config.toml" in rel_lower
        or any(rp.lower().startswith("supabase/migrations/") and rp.lower().endswith(".sql") for rp in rel_paths)
        or bool(npm_deps & {"@supabase/supabase-js", "@supabase/ssr", "@supabase/auth-helpers-nextjs"})
        or cdn_supabase
    )

    has_gas = (
        "appsscript.json" in basenames
        or ".clasp.json" in basenames
        or ".gs" in extensions
    )

    has_laravel = (
        "artisan" in basenames
        or "laravel/framework" in composer_deps
    )
    has_php = has_laravel or ".php" in extensions or composer_json_path.exists()

    has_gh_workflows = any(
        rp.lower().startswith(".github/workflows/") and rp.lower().endswith((".yml", ".yaml"))
        for rp in rel_paths
    )
    has_gh_pages_hints = (
        "cname" in basenames
        or ".nojekyll" in basenames
        or any("pages" in rp.lower() and rp.lower().startswith(".github/workflows/") for rp in rel_paths)
    )

    # Assemble human-readable stack summary
    frontend_parts: list[str] = []
    if has_nextjs:
        frontend_parts.append("Next.js")
    elif has_react and has_vite:
        frontend_parts.append("React / Vite")
    elif has_react:
        frontend_parts.append("React")
    elif has_vue and has_vite:
        frontend_parts.append("Vue / Vite")
    elif has_vue:
        frontend_parts.append("Vue")
    elif has_laravel:
        frontend_parts.append("Laravel Blade / HTML")
    elif has_html:
        frontend_parts.append("Static HTML / JS")

    backend_parts: list[str] = []
    if has_firebase:
        backend_parts.append("Firebase")
    if has_supabase:
        backend_parts.append("Supabase")
    if has_gas:
        backend_parts.append("Google Apps Script")
    if has_laravel:
        backend_parts.append("PHP / Laravel")
    elif has_php:
        backend_parts.append("PHP")
    if has_express_or_node_api:
        backend_parts.append("Node.js API")
    elif has_node and not backend_parts:
        backend_parts.append("Node.js (Build/Tooling)")

    db_parts: list[str] = []
    if has_firestore:
        db_parts.append("Firestore")
    elif has_firebase and not has_rtdb:
        db_parts.append("Firebase (Firestore/RTDB)")
    if has_rtdb:
        db_parts.append("Firebase Realtime DB")
    if has_supabase:
        db_parts.append("Supabase PostgreSQL")
    if has_laravel:
        db_parts.append("SQL / Eloquent (Laravel)")
    if has_gas:
        db_parts.append("Google Sheets / Drive / PropertiesService")

    auth_parts: list[str] = []
    if has_firebase:
        auth_parts.append("Firebase Auth")
    if has_supabase:
        auth_parts.append("Supabase Auth")
    if has_gas:
        auth_parts.append("Google Workspace / Apps Script Session")
    if has_laravel:
        auth_parts.append("Laravel Auth / Session")

    hosting_parts: list[str] = []
    if has_gh_pages_hints or (has_html and not has_php and not has_gas):
        hosting_parts.append("GitHub Pages / Static Hosting")
    if "firebase.json" in basenames:
        hosting_parts.append("Firebase Hosting")
    if "vercel.json" in basenames:
        hosting_parts.append("Vercel")
    if "netlify.toml" in basenames:
        hosting_parts.append("Netlify")
    if has_gas:
        hosting_parts.append("Google Apps Script Web App")
    if not hosting_parts:
        hosting_parts.append("GitHub Repository / Unspecified")

    # Select modular audit profiles
    profiles: list[str] = []
    if has_html or has_gh_pages_hints:
        profiles.append("static-web")
    if has_node or has_react or has_vite or has_nextjs or has_express_or_node_api:
        profiles.append("react-node")
    if has_firebase:
        profiles.append("firebase")
    if has_supabase:
        profiles.append("supabase")
    if has_gas:
        profiles.append("gas")
    if has_php:
        profiles.append("php-laravel")
    if not profiles:
        profiles.append("static-web")

    audit_checks = [
        "Static code security",
        "Secret detection",
        "Web & CI configuration",
    ]
    for prof in profiles:
        label = PROFILE_LABELS.get(prof)
        if label and label not in audit_checks:
            audit_checks.append(label)

    return {
        "project_name": root.name,
        "target_path": str(root),
        "file_count": len(all_files),
        "detection": {
            "frontend": ", ".join(frontend_parts) if frontend_parts else "None detected",
            "backend": ", ".join(backend_parts) if backend_parts else "None (Static / Client-only)",
            "database": ", ".join(db_parts) if db_parts else "None detected",
            "authentication": ", ".join(auth_parts) if auth_parts else "None detected / Custom",
            "hosting": ", ".join(hosting_parts),
        },
        "profiles": profiles,
        "audit_profile_checklist": audit_checks,
        "tooling_applicability": {
            "package_json": package_json_path.exists(),
            "npm_lockfile": (root / "package-lock.json").exists(),
            "composer_json": composer_json_path.exists(),
            "composer_lock": (root / "composer.lock").exists(),
            "github_workflows": has_gh_workflows,
            "firebase_rules": "firestore.rules" in basenames or "storage.rules" in basenames or "database.rules.json" in basenames,
            "supabase_migrations": any(rp.lower().startswith("supabase/migrations/") for rp in rel_paths),
            "gas_manifest": "appsscript.json" in basenames,
        },
    }


def format_human_summary(result: dict[str, Any]) -> str:
    det = result["detection"]
    lines = [
        "==================================================",
        f"PROJECT DETECTION — {result['project_name']}",
        "==================================================",
        f"Frontend       : {det['frontend']}",
        f"Backend        : {det['backend']}",
        f"Database       : {det['database']}",
        f"Authentication : {det['authentication']}",
        f"Hosting        : {det['hosting']}",
        f"Files Scanned  : {result['file_count']}",
        "",
        "AUDIT PROFILE",
        f"Profiles       : {', '.join(result['profiles'])}",
    ]
    for item in result["audit_profile_checklist"]:
        lines.append(f"  [x] {item}")
    lines.append("==================================================")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="WSAS automatic project stack detector")
    parser.add_argument("target", help="Path to the project directory to inspect")
    parser.add_argument("--json", action="store_true", help="Print JSON output to stdout")
    parser.add_argument("--output", help="Optional path to write JSON output")
    args = parser.parse_args()

    try:
        result = detect_stack(args.target)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(format_human_summary(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
