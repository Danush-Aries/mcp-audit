# mcp-audit

**Static security auditor for Claude Code / MCP configuration.** Scan your
`~/.claude.json`, `.mcp.json`, and settings files for supply-chain, credential,
and remote-code-execution risk **before** an agent ever runs them.

MCP config is the new attack surface. In 2026 alone: RCE through Claude Code
project files (CVE-2025-59536), a poisoned-package campaign that silently
rewrote `~/.claude.json` to redirect MCP traffic to attacker infrastructure,
and tens of thousands of hardcoded secrets found sitting in public MCP configs.
`mcp-audit` catches these patterns in one offline command.

## Install

```bash
uv tool install mcp-audit          # or: pipx install mcp-audit
```

Or run without installing:

```bash
uvx mcp-audit
```

## Usage

```bash
# Scan all known Claude/MCP config locations on this machine
mcp-audit

# Scan specific files
mcp-audit ~/.claude.json .mcp.json

# Machine-readable output for CI
mcp-audit --json

# Gate CI: exit non-zero on any HIGH-or-worse finding (default)
mcp-audit --fail-on HIGH
```

Exit code is `1` when a finding at or above `--fail-on` (default `HIGH`) is
present, `0` otherwise — so you can drop it straight into a pre-commit hook or
CI step.

## What it checks

| Rule | Severity | Detects |
|------|----------|---------|
| `SECRET001/002` | CRITICAL | Hardcoded API keys / tokens in server `env` or `args` (pattern + entropy) |
| `REGISTRY001` | CRITICAL | Typosquatted package scopes (e.g. `@modelcontextprotocl/…`) |
| `REGISTRY002/003/004` | HIGH | Non-HTTPS endpoints, raw-IP hosts, URL-shortener redirects |
| `HOOK001/003` | CRITICAL | Hooks / server commands that rewrite MCP config from the network |
| `HOOK002/004` | HIGH | Fetch-and-execute (`curl … | bash`) in hooks or server launch |
| `PIN001/002` | MEDIUM | Servers pinned to `@latest` or installed with no version at all |
| `PERM001` | HIGH | Credential-bearing config readable by group/other |

Everything runs locally and offline — `mcp-audit` never makes a network call
and never sends your config anywhere.

## How it works

1. **Load** — finds and parses config, flattening every server-map shape
   (`mcpServers`, `servers`, `mcp.servers`, and per-project nesting in
   `~/.claude.json`) into one normalized list.
2. **Scan** — five independent scanners each return severity-ranked findings.
3. **Report** — a `rich` table for humans, or `--json` for machines, with a
   concrete remediation line per finding.

## Development

```bash
git clone https://github.com/Danush-Aries/mcp-audit
cd mcp-audit
uv run --extra dev pytest -q
```

Test fixtures store fake tokens with a `%SPLIT%` sentinel that the harness
strips at load time, so the repo never contains a literal that would trip
secret scanning.

## License

MIT
