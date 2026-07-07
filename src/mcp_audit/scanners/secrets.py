"""Detect hardcoded secrets embedded in MCP config (env values and args).

Two layers, mirroring the approach proven in envsentry:
  1. High-signal provider patterns (AWS, GitHub, OpenAI, Slack, Stripe, ...).
  2. Shannon-entropy fallback for long opaque strings that look like keys.

Test fixtures split real-looking tokens with a ``%SPLIT%`` sentinel that the
test harness strips at load time, so this source file never contains a literal
that would trip GitHub secret scanning — and, importantly, we do NOT rebuild
detection by adjacent-splitting scanned literals here.
"""

from __future__ import annotations

import math
import re
from typing import Any

from ..rules import ConfigFile, Finding, Severity

# name -> compiled pattern. Kept deliberately tight to limit false positives.
_PROVIDER_PATTERNS: dict[str, re.Pattern[str]] = {
    "AWS access key id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh[posru]_[A-Za-z0-9]{36,255}\b"),
    "OpenAI key": re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    "Anthropic key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "Stripe secret key": re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"),
    "Private key block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Generic bearer JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
}

# Env keys whose *name* implies a secret; value scanned even without a pattern hit.
_SECRETISH_KEY = re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|credential)")

# Values that are clearly placeholders, not real leaks.
_PLACEHOLDER = re.compile(r"(?i)^(\$\{.*\}|<.*>|your[_-].*|xxx+|changeme|example|dummy|redacted|\.\.\.)$")

_ENTROPY_MIN_LEN = 24
_ENTROPY_THRESHOLD = 4.0  # bits/char; random base64 sits ~4.5–6.0.


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_secret(value: str) -> bool:
    v = value.strip()
    if len(v) < _ENTROPY_MIN_LEN or _PLACEHOLDER.match(v):
        return False
    # Long, high-entropy, and not a sentence with spaces.
    return " " not in v and _shannon_entropy(v) >= _ENTROPY_THRESHOLD


def _scan_value(value: Any, *, use_entropy: bool = True) -> str | None:
    """Return the provider name if a pattern matches, else 'entropy', else None.

    ``use_entropy`` is disabled for argv scanning: package specs and file paths
    are long and high-entropy but not secrets, so on the command line we trust
    only the explicit provider patterns.
    """
    if not isinstance(value, str):
        return None
    for name, pat in _PROVIDER_PATTERNS.items():
        if pat.search(value):
            return name
    if use_entropy and _looks_secret(value):
        return "entropy"
    return None


def scan(cfg: ConfigFile) -> list[Finding]:
    findings: list[Finding] = []
    for srv in cfg.servers:
        # env values
        for key, val in srv.env.items():
            hit = _scan_value(val)
            key_is_secretish = bool(_SECRETISH_KEY.search(key))
            if hit or (key_is_secretish and isinstance(val, str) and not _PLACEHOLDER.match(val.strip()) and len(val.strip()) >= 12):
                kind = hit or "credential-named env value"
                findings.append(
                    Finding(
                        rule_id="SECRET001",
                        severity=Severity.CRITICAL,
                        title="Hardcoded secret in MCP server env",
                        detail=f"Server '{srv.name}' stores an apparent {kind} inline in its env.",
                        remediation="Move the value to an environment variable or secret manager and "
                        "reference it (e.g. \"${GITHUB_TOKEN}\"). Rotate the exposed credential.",
                        file=cfg.path,
                        location=f"mcpServers.{srv.name}.env.{key}",
                    )
                )
        # args (secrets are often passed as --token <value>)
        for i, arg in enumerate(srv.args):
            hit = _scan_value(arg, use_entropy=False)
            if hit:
                findings.append(
                    Finding(
                        rule_id="SECRET002",
                        severity=Severity.CRITICAL,
                        title="Hardcoded secret in MCP server args",
                        detail=f"Server '{srv.name}' passes an apparent {hit} on the command line.",
                        remediation="Pass secrets via env references, not argv (argv is visible in process "
                        "listings). Rotate the exposed credential.",
                        file=cfg.path,
                        location=f"mcpServers.{srv.name}.args[{i}]",
                    )
                )
    return findings
