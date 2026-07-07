"""Scanner registry. Each scanner is a ``scan(ConfigFile) -> list[Finding]``."""

from __future__ import annotations

from typing import Callable

from ..rules import ConfigFile, Finding
from . import hooks, permissions, pinning, registry, secrets

Scanner = Callable[[ConfigFile], list[Finding]]

# Order is cosmetic only; findings are sorted by severity in the reporter.
ALL_SCANNERS: list[Scanner] = [
    secrets.scan,
    registry.scan,
    hooks.scan,
    pinning.scan,
    permissions.scan,
]


def run_all(cfg: ConfigFile) -> list[Finding]:
    findings: list[Finding] = []
    for scanner in ALL_SCANNERS:
        findings.extend(scanner(cfg))
    return findings
