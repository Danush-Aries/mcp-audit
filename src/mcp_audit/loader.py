"""Locate, parse, and normalize Claude Code / MCP configuration files.

MCP servers are spelled differently across hosts and files:
  * ``.mcp.json``            -> {"mcpServers": {...}}
  * Claude Desktop config    -> {"mcpServers": {...}}
  * ``~/.claude.json``       -> {"mcpServers": {...}} and per-project nesting
  * VS Code / Cursor         -> {"servers": {...}} or {"mcp": {"servers": {...}}}

The loader flattens all of these into a list of ``ServerSpec`` so scanners
never have to care about the surrounding shape.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable

from .rules import ConfigFile, ServerSpec

# Default locations checked when the user passes no explicit path.
DEFAULT_TARGETS = [
    "~/.claude.json",
    "~/.claude/settings.json",
    "~/.claude/settings.local.json",
    "~/Library/Application Support/Claude/claude_desktop_config.json",
    ".mcp.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
]


class ConfigError(Exception):
    """Raised when a target exists but cannot be parsed as JSON."""


def default_paths() -> list[Path]:
    out: list[Path] = []
    for t in DEFAULT_TARGETS:
        p = Path(t).expanduser()
        if p.exists():
            out.append(p)
    return out


def _server_map(data: dict[str, Any]) -> dict[str, Any]:
    """Return the server dict regardless of which key the host used."""
    if isinstance(data.get("mcpServers"), dict):
        return data["mcpServers"]
    if isinstance(data.get("servers"), dict):
        return data["servers"]
    mcp = data.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        return mcp["servers"]
    return {}


def _iter_server_maps(data: dict[str, Any]) -> Iterable[dict[str, Any]]:
    """Yield every server map in the file, including per-project nesting.

    ``~/.claude.json`` nests config under ``projects.<path>.mcpServers``; a
    malicious repo commit lands there, so we must descend into it.
    """
    top = _server_map(data)
    if top:
        yield top
    projects = data.get("projects")
    if isinstance(projects, dict):
        for proj in projects.values():
            if isinstance(proj, dict):
                nested = _server_map(proj)
                if nested:
                    yield nested


def _normalize_servers(data: dict[str, Any]) -> list[ServerSpec]:
    specs: list[ServerSpec] = []
    for smap in _iter_server_maps(data):
        for name, spec in smap.items():
            if not isinstance(spec, dict):
                continue
            specs.append(
                ServerSpec(
                    name=name,
                    command=str(spec.get("command", "")),
                    args=[str(a) for a in spec.get("args", []) if a is not None],
                    env=dict(spec.get("env", {})) if isinstance(spec.get("env"), dict) else {},
                    url=str(spec.get("url", "")),
                    raw=spec,
                )
            )
    return specs


def load_config(path: Path) -> ConfigFile:
    """Parse a single config file into a ``ConfigFile``.

    Raises ``ConfigError`` on malformed JSON so the CLI can report it as a
    scan error rather than crashing.
    """
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text) if text.strip() else {}
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path}: invalid JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top-level JSON is not an object")

    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        mode = 0o600

    return ConfigFile(
        path=path,
        data=data,
        servers=_normalize_servers(data),
        mode=mode,
    )
