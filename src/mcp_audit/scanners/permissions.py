"""Flag config files that expose credentials via loose filesystem permissions.

A ``~/.claude.json`` containing OAuth tokens or API keys that is group- or
world-readable (CVE-2025-59536 class) lets any local process read them. This
scanner only fires when the file both (a) is readable beyond the owner and
(b) actually contains credential material.
"""

from __future__ import annotations

import re
import stat
from typing import Any

from ..rules import ConfigFile, Finding, Severity

_CRED_KEY = re.compile(r"(?i)(token|secret|api[_-]?key|access[_-]?key|password|oauth|credential|bearer)")
# A value that is a placeholder or env reference is not real credential material.
_NOT_A_SECRET = re.compile(r"(?i)^\s*(\$\{.*\}|\$[A-Z_][A-Z0-9_]*|<.*>|your[_-].*|changeme|example|dummy|redacted|)\s*$")


def _walk(obj: Any):
    """Yield (key, value) pairs for every string value in a nested structure."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str):
                yield k, v
            else:
                yield from _walk(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk(item)


def _contains_credentials(cfg: ConfigFile) -> bool:
    """True only if a credential-named key holds a real (non-placeholder) value."""
    for key, value in _walk(cfg.data):
        if _CRED_KEY.search(key) and not _NOT_A_SECRET.match(value) and len(value.strip()) >= 8:
            return True
    return False


def scan(cfg: ConfigFile) -> list[Finding]:
    findings: list[Finding] = []
    group_or_other_readable = bool(cfg.mode & (stat.S_IRGRP | stat.S_IROTH))
    if group_or_other_readable and _contains_credentials(cfg):
        findings.append(
            Finding(
                rule_id="PERM001",
                severity=Severity.HIGH,
                title="Credential-bearing config is readable beyond its owner",
                detail=f"{cfg.path} has mode {oct(cfg.mode)} and contains credential material; any local "
                "user/process can read it.",
                remediation=f"Restrict permissions: chmod 600 {cfg.path}. Rotate any exposed tokens.",
                file=cfg.path,
                location="<file mode>",
            )
        )
    return findings
