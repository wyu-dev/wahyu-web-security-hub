#!/usr/bin/env python3
"""Secret redaction utilities for WSAS.

Ensures raw API keys, tokens, passwords, connection strings, and private keys
are never persisted in audit logs, Markdown/JSON reports, or sent to AI providers.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

# Ordered from most specific/multi-line to generic key=value assignments.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "private_key_block",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.MULTILINE,
        ),
        "[REDACTED:PRIVATE_KEY_BLOCK]",
    ),
    (
        "private_key_header",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
        "[REDACTED:PRIVATE_KEY_HEADER]",
    ),
    (
        "openrouter_or_openai_key",
        re.compile(r"\bsk-(?:or-v1-|proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b"),
        "[REDACTED:API_SECRET_KEY]",
    ),
    (
        "stripe_key",
        re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"),
        "[REDACTED:STRIPE_KEY]",
    ),
    (
        "github_token",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
        "[REDACTED:GITHUB_TOKEN]",
    ),
    (
        "aws_access_key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "[REDACTED:AWS_ACCESS_KEY]",
    ),
    (
        "slack_token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "[REDACTED:SLACK_TOKEN]",
    ),
    (
        "google_api_key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35,45}\b"),
        "[REDACTED:GOOGLE_API_KEY]",
    ),
    (
        "jwt_token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "[REDACTED:JWT]",
    ),
    (
        "connection_string_creds",
        re.compile(r"((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)://[^:\s/@]+:)([^@\s]+)(@)"),
        r"\1[REDACTED:DB_PASSWORD]\3",
    ),
    (
        "bearer_token",
        re.compile(r"(?i)(Bearer\s+)([A-Za-z0-9._~+/=-]{16,})"),
        r"\1[REDACTED:BEARER_TOKEN]",
    ),
    (
        "env_or_config_secret",
        re.compile(
            r"(?i)(\b(?:password|passwd|pwd|secret|api_?secret|access_?token|auth_?token|private_?key|"
            r"service_?role_?key|db_password|app_key|jwt_secret|openrouter_api_key|openai_api_key|"
            r"stripe_secret|client_secret)\b\s*[:=]\s*['\"]?)([^'\"\s,;}{]{4,})(['\"]?)"
        ),
        r"\1[REDACTED]\3",
    ),
]


def redact_text(text: str) -> str:
    """Return a copy of text with known credential patterns masked."""
    if not text:
        return text
    result = text
    for _name, pattern, replacement in SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def redact_obj(value: Any) -> Any:
    """Recursively redact all strings inside nested dicts/lists."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_obj(item) for item in value]
    if isinstance(value, dict):
        return {k: redact_obj(v) for k, v in value.items()}
    return value


def contains_unredacted_secret(text: str) -> list[str]:
    """Return names of any high-confidence secret patterns still present in text."""
    if not text:
        return []
    matches: list[str] = []
    # Check high-confidence token patterns (excluding generic key=value which may have [REDACTED]).
    strict_names = {
        "private_key_block",
        "private_key_header",
        "openrouter_or_openai_key",
        "stripe_key",
        "github_token",
        "aws_access_key",
        "slack_token",
        "jwt_token",
    }
    for name, pattern, _replacement in SECRET_PATTERNS:
        if name in strict_names and pattern.search(text):
            matches.append(name)
    return matches
