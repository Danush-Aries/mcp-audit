"""Core data model: severities, findings, and the config records scanners consume."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class Severity(enum.IntEnum):
    """Ordered so comparisons work: CRITICAL > HIGH > MEDIUM > LOW > INFO."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        return cls[name.strip().upper()]


# Rich style per severity, used by the reporter.
SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


@dataclass(frozen=True)
class Finding:
    """A single issue discovered by a scanner.

    `rule_id` is a stable short code (e.g. ``SECRET001``) so findings can be
    filtered, suppressed, or referenced in CI logs without matching on prose.
    """

    rule_id: str
    severity: Severity
    title: str
    detail: str
    remediation: str
    file: Path
    location: str = ""  # e.g. "mcpServers.github.env.GITHUB_TOKEN"

    def sort_key(self) -> tuple:
        # Highest severity first, then grouped by file and rule for stable output.
        return (-int(self.severity), str(self.file), self.rule_id, self.location)


@dataclass
class ServerSpec:
    """A normalized view of one MCP server entry, however the host spelled it."""

    name: str
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, Any] = field(default_factory=dict)
    url: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ConfigFile:
    """A parsed configuration file plus everything scanners need from it."""

    path: Path
    data: dict[str, Any]
    servers: list[ServerSpec] = field(default_factory=list)
    mode: int = 0o600  # POSIX permission bits; 0o600 is a safe default for tests.
