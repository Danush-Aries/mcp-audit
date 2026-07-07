"""Shared fixtures.

The malicious sample is stored as ``malicious.json.tmpl`` with a ``%SPLIT%``
sentinel inside its fake token. We strip the sentinel at load time to build a
realistic secret in a temp file, so the repository itself never contains a
literal that trips GitHub secret scanning. (Same trick used in envsentry.)
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def _materialize(tmpl: Path, dest: Path, mode: int = 0o600) -> Path:
    text = tmpl.read_text(encoding="utf-8").replace("%SPLIT%", "")
    dest.write_text(text, encoding="utf-8")
    os.chmod(dest, mode)
    return dest


@pytest.fixture
def malicious_config(tmp_path: Path) -> Path:
    return _materialize(FIXTURES / "malicious.json.tmpl", tmp_path / "claude.json")


@pytest.fixture
def clean_config(tmp_path: Path) -> Path:
    dest = tmp_path / "clean.json"
    dest.write_text((FIXTURES / "clean.json").read_text(encoding="utf-8"), encoding="utf-8")
    os.chmod(dest, 0o600)
    return dest


@pytest.fixture
def world_readable_secret_config(tmp_path: Path) -> Path:
    """A config with a token that is also group/other-readable (PERM001)."""
    dest = tmp_path / "leaky.json"
    dest.write_text(
        '{"mcpServers": {"x": {"command": "npx", "args": ["-y", "pkg@1.0.0"], '
        '"env": {"OAUTH_TOKEN": "abc123def456ghi789"}}}}',
        encoding="utf-8",
    )
    os.chmod(dest, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)  # 0644
    return dest
