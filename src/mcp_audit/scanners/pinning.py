"""Flag MCP servers installed from unpinned package specs.

An ``npx -y foo@latest`` (or a bare ``foo`` with no version) resolves to
whatever the registry serves at launch time — so a compromised or newly
published malicious version runs with no review. Pinning to an exact version
(ideally with a lockfile) closes that window.
"""

from __future__ import annotations

import re

from ..rules import ConfigFile, Finding, Severity

_PKG_RUNNERS = {"npx", "npm", "pnpm", "yarn", "uvx", "pipx", "bunx"}
# A pinned spec ends with @<exact-version>, e.g. name@1.2.3 or @scope/name@1.2.3.
_PINNED = re.compile(r"@\d+\.\d+\.\d+([-.+][0-9A-Za-z.-]+)?$")
_EXPLICIT_LATEST = re.compile(r"@(latest|next|canary|\*)$")


def _package_spec(command: str, args: list[str]) -> str | None:
    cmd = command.rsplit("/", 1)[-1]
    if cmd not in _PKG_RUNNERS:
        return None
    for a in args:
        if a.startswith("-"):  # skip flags like -y, --yes
            continue
        return a
    return None


def scan(cfg: ConfigFile) -> list[Finding]:
    findings: list[Finding] = []
    for srv in cfg.servers:
        spec = _package_spec(srv.command, srv.args)
        if spec is None:
            continue
        if _EXPLICIT_LATEST.search(spec):
            findings.append(
                Finding(
                    rule_id="PIN001",
                    severity=Severity.MEDIUM,
                    title="MCP server pinned to a moving tag",
                    detail=f"Server '{srv.name}' installs '{spec}', which resolves to whatever is newest at launch.",
                    remediation="Pin to an exact version (e.g. name@1.4.2) and commit a lockfile so the code "
                    "you reviewed is the code that runs.",
                    file=cfg.path,
                    location=f"mcpServers.{srv.name}.args",
                )
            )
        elif "@" not in spec.lstrip("@") and _PINNED.search(spec) is None:
            # bare package name, no version at all
            findings.append(
                Finding(
                    rule_id="PIN002",
                    severity=Severity.MEDIUM,
                    title="MCP server installed without a pinned version",
                    detail=f"Server '{srv.name}' installs '{spec}' with no version constraint.",
                    remediation="Add an exact version (name@x.y.z). Unpinned installs silently adopt new, "
                    "unreviewed releases.",
                    file=cfg.path,
                    location=f"mcpServers.{srv.name}.args",
                )
            )
    return findings
