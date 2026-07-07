"""Top-level orchestration: given paths, produce sorted findings + a summary."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .loader import ConfigError, load_config
from .rules import Finding, Severity
from .scanners import run_all


@dataclass
class AuditResult:
    findings: list[Finding] = field(default_factory=list)
    scanned: list[Path] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[Severity, int]:
        out = {s: 0 for s in Severity}
        for f in self.findings:
            out[f.severity] += 1
        return out

    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)


def audit_paths(paths: list[Path]) -> AuditResult:
    result = AuditResult()
    for path in paths:
        try:
            cfg = load_config(path)
        except ConfigError as exc:
            result.errors.append(str(exc))
            continue
        except OSError as exc:
            result.errors.append(f"{path}: {exc}")
            continue
        result.scanned.append(path)
        result.findings.extend(run_all(cfg))
    result.findings.sort(key=Finding.sort_key)
    return result
