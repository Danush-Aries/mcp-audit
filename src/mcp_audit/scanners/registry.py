"""Flag MCP servers that pull code from untrusted or suspicious sources.

Covers two 2026 attack shapes:
  * Typosquatted package specs (e.g. ``@modelcontextprotocl/...``).
  * Remote server URLs pointing at raw IPs, non-HTTPS, or shortener/redirect
    hosts — the "Comment and Control" pattern where an MCP endpoint is swapped
    for attacker infrastructure.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from ..rules import ConfigFile, Finding, Severity

# Publisher scopes / hosts generally considered first-party or well-known.
_TRUSTED_SCOPES = (
    "@modelcontextprotocol/",
    "@anthropic-ai/",
    "@github/",
    "@cloudflare/",
    "@notionhq/",
    "@supabase/",
)

# Known-good npm scope spellings; anything one edit away is a typosquat suspect.
_CANONICAL_SCOPES = ("modelcontextprotocol", "anthropic-ai", "anthropic")

_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rebrand.ly",
}

_PKG_RUNNERS = {"npx", "npm", "pnpm", "yarn", "uvx", "pipx", "bunx"}


def _levenshtein_le1(a: str, b: str) -> bool:
    """True if a and b differ by at most one edit. Cheap early-exit version."""
    if a == b:
        return False  # identical isn't a typosquat
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    # Ensure a is the shorter/equal.
    if la > lb:
        a, b, la, lb = b, a, lb, la
    i = j = 0
    edits = 0
    while i < la and j < lb:
        if a[i] == b[j]:
            i += 1
            j += 1
        else:
            edits += 1
            if edits > 1:
                return False
            if la == lb:
                i += 1
                j += 1
            else:
                j += 1  # deletion in longer string
    edits += (la - i) + (lb - j)
    return edits == 1


def _scope_of(spec: str) -> str:
    m = re.match(r"@([^/]+)/", spec)
    return m.group(1) if m else ""


def _check_package_specs(cfg: ConfigFile) -> list[Finding]:
    findings: list[Finding] = []
    for srv in cfg.servers:
        cmd = srv.command.rsplit("/", 1)[-1]
        if cmd not in _PKG_RUNNERS:
            continue
        # The package spec is the first non-flag arg.
        spec = next((a for a in srv.args if not a.startswith("-")), "")
        if not spec:
            continue
        scope = _scope_of(spec)
        if scope:
            for canon in _CANONICAL_SCOPES:
                if _levenshtein_le1(scope.lower(), canon):
                    findings.append(
                        Finding(
                            rule_id="REGISTRY001",
                            severity=Severity.CRITICAL,
                            title="Possible typosquatted MCP package scope",
                            detail=f"Server '{srv.name}' installs '{spec}', whose scope '@{scope}' is "
                            f"one edit from the legitimate '@{canon}'.",
                            remediation=f"Verify the publisher. If you meant '@{canon}', correct the spec; "
                            "otherwise remove this server.",
                            file=cfg.path,
                            location=f"mcpServers.{srv.name}.args",
                        )
                    )
                    break
    return findings


def _check_urls(cfg: ConfigFile) -> list[Finding]:
    findings: list[Finding] = []
    for srv in cfg.servers:
        if not srv.url:
            continue
        parsed = urlparse(srv.url)
        host = (parsed.hostname or "").lower()

        # Non-HTTPS remote endpoint => traffic (and tokens) sent in cleartext.
        if parsed.scheme and parsed.scheme not in ("https", "stdio") and host not in ("localhost", "127.0.0.1"):
            findings.append(
                Finding(
                    rule_id="REGISTRY002",
                    severity=Severity.HIGH,
                    title="MCP server endpoint is not HTTPS",
                    detail=f"Server '{srv.name}' connects to '{srv.url}' over '{parsed.scheme}'.",
                    remediation="Use an https:// endpoint so requests and credentials are encrypted in transit.",
                    file=cfg.path,
                    location=f"mcpServers.{srv.name}.url",
                )
            )

        # Raw IP literal instead of a named, certificate-bearing host.
        if host:
            try:
                ipaddress.ip_address(host)
                is_ip = True
            except ValueError:
                is_ip = False
            if is_ip and host not in ("127.0.0.1", "::1"):
                findings.append(
                    Finding(
                        rule_id="REGISTRY003",
                        severity=Severity.HIGH,
                        title="MCP server endpoint is a raw IP address",
                        detail=f"Server '{srv.name}' points at IP literal '{host}' rather than a named host.",
                        remediation="Point the server at a verified domain; raw IPs bypass certificate "
                        "identity checks and are a common redirect-to-attacker indicator.",
                        file=cfg.path,
                        location=f"mcpServers.{srv.name}.url",
                    )
                )
            if host in _URL_SHORTENERS:
                findings.append(
                    Finding(
                        rule_id="REGISTRY004",
                        severity=Severity.HIGH,
                        title="MCP server endpoint hidden behind a URL shortener",
                        detail=f"Server '{srv.name}' resolves through '{host}', masking the true destination.",
                        remediation="Replace the shortened URL with the direct, verified endpoint.",
                        file=cfg.path,
                        location=f"mcpServers.{srv.name}.url",
                    )
                )
    return findings


def scan(cfg: ConfigFile) -> list[Finding]:
    return _check_package_specs(cfg) + _check_urls(cfg)
