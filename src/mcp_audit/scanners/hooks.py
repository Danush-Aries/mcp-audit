"""Detect command injection: hooks that run shell, or commands that rewrite config.

The Feb 2026 poisoned-package attack worked by having an MCP server's command
(or a settings hook) silently rewrite ``~/.claude.json`` to redirect MCP
traffic to attacker infrastructure. This scanner inspects:
  * ``hooks`` blocks in settings for shell commands touching config/network.
  * MCP server ``command``/``args`` that pipe-to-shell or self-modify config.
"""

from __future__ import annotations

import re
from typing import Any

from ..rules import ConfigFile, Finding, Severity

# Commands that rewrite Claude/MCP config or fetch-and-execute remote code.
_CONFIG_REWRITE = re.compile(r"(?i)(\.claude(?:\.json)?|\.mcp\.json|settings\.local\.json)")
_FETCH_EXEC = re.compile(
    r"(?i)(curl|wget)\b[^|&;]*(\||&&|;)\s*(sh|bash|zsh|python3?|node|eval)\b"
    r"|\b(sh|bash)\s+-c\b"
    r"|\beval\b"
    r"|\bbase64\s+-d\b[^|]*\|\s*(sh|bash)"
)
_NET_TOOLS = re.compile(r"(?i)\b(curl|wget|nc|ncat|socat)\b")


def _cmd_text(*parts: Any) -> str:
    out: list[str] = []
    for p in parts:
        if isinstance(p, str):
            out.append(p)
        elif isinstance(p, (list, tuple)):
            out.extend(str(x) for x in p)
    return " ".join(out)


def _scan_hooks_block(cfg: ConfigFile) -> list[Finding]:
    findings: list[Finding] = []
    hooks = cfg.data.get("hooks")
    if not isinstance(hooks, dict):
        return findings
    for event, spec in hooks.items():
        # Normalize the many shapes hooks can take into a flat list of command strings.
        commands: list[str] = []
        entries = spec if isinstance(spec, list) else [spec]
        for entry in entries:
            if isinstance(entry, str):
                commands.append(entry)
            elif isinstance(entry, dict):
                if isinstance(entry.get("command"), str):
                    commands.append(entry["command"])
                for h in entry.get("hooks", []) if isinstance(entry.get("hooks"), list) else []:
                    if isinstance(h, dict) and isinstance(h.get("command"), str):
                        commands.append(h["command"])
        for cmd in commands:
            if _CONFIG_REWRITE.search(cmd) and _NET_TOOLS.search(cmd):
                findings.append(
                    Finding(
                        rule_id="HOOK001",
                        severity=Severity.CRITICAL,
                        title="Hook rewrites MCP config from a network source",
                        detail=f"The '{event}' hook runs a command that touches Claude/MCP config and "
                        f"makes network calls: {cmd[:120]}",
                        remediation="Remove this hook. Config-rewriting hooks that fetch from the network are "
                        "the exact vector used to hijack MCP routing (Feb 2026 poisoned-package attack).",
                        file=cfg.path,
                        location=f"hooks.{event}",
                    )
                )
            elif _FETCH_EXEC.search(cmd):
                findings.append(
                    Finding(
                        rule_id="HOOK002",
                        severity=Severity.HIGH,
                        title="Hook fetches and executes remote code",
                        detail=f"The '{event}' hook pipes remote content into a shell/interpreter: {cmd[:120]}",
                        remediation="Do not fetch-and-execute in hooks. Vendor the script, review it, and run "
                        "a pinned local copy.",
                        file=cfg.path,
                        location=f"hooks.{event}",
                    )
                )
    return findings


def _scan_server_commands(cfg: ConfigFile) -> list[Finding]:
    findings: list[Finding] = []
    for srv in cfg.servers:
        text = _cmd_text(srv.command, srv.args)
        if _CONFIG_REWRITE.search(text) and _NET_TOOLS.search(text):
            findings.append(
                Finding(
                    rule_id="HOOK003",
                    severity=Severity.CRITICAL,
                    title="MCP server command rewrites config from network",
                    detail=f"Server '{srv.name}' runs a command that both touches config and calls the network.",
                    remediation="Inspect this server's command; a legitimate MCP server does not rewrite your "
                    "Claude/MCP config. Remove it if unexplained.",
                    file=cfg.path,
                    location=f"mcpServers.{srv.name}.command",
                )
            )
        elif _FETCH_EXEC.search(text):
            findings.append(
                Finding(
                    rule_id="HOOK004",
                    severity=Severity.HIGH,
                    title="MCP server command fetches and executes remote code",
                    detail=f"Server '{srv.name}' pipes remote content into a shell/interpreter at launch.",
                    remediation="Replace with a reviewed, pinned local entrypoint. Fetch-and-exec at launch "
                    "means the code you run can change under you at any time.",
                    file=cfg.path,
                    location=f"mcpServers.{srv.name}.command",
                )
            )
    return findings


def scan(cfg: ConfigFile) -> list[Finding]:
    return _scan_hooks_block(cfg) + _scan_server_commands(cfg)
