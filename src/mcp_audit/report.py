"""Render an ``AuditResult`` as a human table (rich) or machine JSON."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .engine import AuditResult
from .rules import SEVERITY_STYLE, Finding, Severity


def to_json(result: AuditResult) -> str:
    payload: dict[str, Any] = {
        "scanned": [str(p) for p in result.scanned],
        "errors": result.errors,
        "summary": {s.label: result.counts[s] for s in reversed(Severity)},
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.label,
                "title": f.title,
                "detail": f.detail,
                "remediation": f.remediation,
                "file": str(f.file),
                "location": f.location,
            }
            for f in result.findings
        ],
    }
    return json.dumps(payload, indent=2)


def _finding_row(f: Finding) -> tuple[str, str, str, str]:
    sev = f"[{SEVERITY_STYLE[f.severity]}] {f.severity.label} [/]"
    where = f"{f.file}\n{f.location}" if f.location else str(f.file)
    body = f"[bold]{f.title}[/]\n{f.detail}\n[dim]→ {f.remediation}[/]"
    return sev, f.rule_id, where, body


def render(result: AuditResult, console: Console | None = None) -> None:
    console = console or Console()

    if not result.scanned and not result.errors:
        console.print("[yellow]No config files found to scan.[/]")
        return

    for err in result.errors:
        console.print(f"[red]! parse error:[/] {err}")

    if not result.findings:
        console.print(
            Panel(
                f"[green]No issues found across {len(result.scanned)} file(s).[/]",
                title="mcp-audit",
                border_style="green",
            )
        )
        return

    table = Table(show_lines=True, expand=True, title="mcp-audit findings")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Where", overflow="fold")
    table.add_column("Issue", overflow="fold")
    for f in result.findings:
        table.add_row(*_finding_row(f))
    console.print(table)

    counts = result.counts
    summary = "  ".join(
        f"[{SEVERITY_STYLE[s]}]{s.label}: {counts[s]}[/]"
        for s in reversed(Severity)
        if counts[s]
    )
    console.print(Panel(summary, title="Summary", border_style="red"))
