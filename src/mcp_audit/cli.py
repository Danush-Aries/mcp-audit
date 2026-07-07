"""Command-line entry point for mcp-audit."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console

from . import __version__
from .engine import audit_paths
from .loader import default_paths
from .report import render, to_json
from .rules import Severity


def _fail_severity(name: str) -> Severity:
    try:
        return Severity.from_name(name)
    except KeyError:
        raise argparse.ArgumentTypeError(
            f"invalid severity '{name}'; choose from {[s.label for s in Severity]}"
        )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcp-audit",
        description="Static security auditor for Claude Code / MCP config files.",
    )
    p.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="Config files to scan. Defaults to known Claude/MCP locations if omitted.",
    )
    p.add_argument("--json", action="store_true", help="Emit findings as JSON.")
    p.add_argument(
        "--fail-on",
        type=_fail_severity,
        default=Severity.HIGH,
        metavar="SEVERITY",
        help="Exit non-zero when a finding at or above this severity exists (default: HIGH).",
    )
    p.add_argument("--version", action="version", version=f"mcp-audit {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = args.paths or default_paths()

    if not paths:
        Console(stderr=True).print(
            "[yellow]No config files given and no default Claude/MCP config found.[/]"
        )
        return 0

    result = audit_paths(paths)

    if args.json:
        print(to_json(result))
    else:
        render(result)

    top = result.max_severity()
    if top is not None and top >= args.fail_on:
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
