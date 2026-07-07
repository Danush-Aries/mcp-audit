"""End-to-end and per-scanner tests."""

from __future__ import annotations

from pathlib import Path

from mcp_audit.cli import main
from mcp_audit.engine import audit_paths
from mcp_audit.loader import load_config
from mcp_audit.rules import Severity
from mcp_audit.scanners import hooks, permissions, pinning, registry, secrets


def _rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


# --- clean config: no findings, exit 0 ---------------------------------------


def test_clean_config_has_no_findings(clean_config: Path):
    result = audit_paths([clean_config])
    assert result.findings == []
    assert result.max_severity() is None


def test_cli_exit_zero_on_clean(clean_config: Path, capsys):
    assert main([str(clean_config)]) == 0


# --- malicious config: each scanner fires ------------------------------------


def test_malicious_config_is_critical(malicious_config: Path):
    result = audit_paths([malicious_config])
    assert result.max_severity() == Severity.CRITICAL
    ids = _rule_ids(result.findings)
    # secret in env, typosquat, fetch-exec/config-rewrite, raw IP, unpinned
    assert "SECRET001" in ids
    assert "REGISTRY001" in ids
    assert "REGISTRY003" in ids
    assert {"HOOK001", "HOOK002", "HOOK003"} & ids
    assert {"PIN001", "PIN002"} & ids


def test_cli_exit_nonzero_on_malicious(malicious_config: Path, capsys):
    assert main([str(malicious_config)]) == 1


def test_cli_json_output(malicious_config: Path, capsys):
    main([str(malicious_config), "--json"])
    out = capsys.readouterr().out
    assert '"severity": "CRITICAL"' in out
    assert '"rule_id"' in out


# --- targeted scanner behavior ------------------------------------------------


def test_secret_detection_ignores_env_reference(clean_config: Path):
    cfg = load_config(clean_config)
    assert secrets.scan(cfg) == []  # ${GITHUB_TOKEN} is a reference, not a leak


def test_typosquat_flags_near_miss_but_not_exact(malicious_config: Path, clean_config: Path):
    assert "REGISTRY001" in _rule_ids(registry.scan(load_config(malicious_config)))
    assert "REGISTRY001" not in _rule_ids(registry.scan(load_config(clean_config)))


def test_pinning_flags_latest_and_bare(malicious_config: Path):
    ids = _rule_ids(pinning.scan(load_config(malicious_config)))
    assert "PIN001" in ids  # @latest
    assert "PIN002" in ids  # bare "some-mcp-tool"


def test_hooks_flag_config_rewrite(malicious_config: Path):
    ids = _rule_ids(hooks.scan(load_config(malicious_config)))
    assert "HOOK001" in ids  # hook curls into ~/.claude.json


def test_permissions_flag_world_readable_secret(world_readable_secret_config: Path):
    cfg = load_config(world_readable_secret_config)
    assert "PERM001" in _rule_ids(permissions.scan(cfg))


def test_permissions_ok_when_owner_only(clean_config: Path):
    cfg = load_config(clean_config)
    assert permissions.scan(cfg) == []


# --- loader robustness --------------------------------------------------------


def test_invalid_json_reported_as_error(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid", encoding="utf-8")
    result = audit_paths([bad])
    assert result.errors
    assert result.findings == []


def test_vscode_servers_key_is_understood(tmp_path: Path):
    p = tmp_path / "mcp.json"
    p.write_text('{"servers": {"a": {"command": "npx", "args": ["pkg"]}}}', encoding="utf-8")
    cfg = load_config(p)
    assert len(cfg.servers) == 1
    assert cfg.servers[0].name == "a"


def test_projects_nesting_is_scanned(tmp_path: Path):
    p = tmp_path / "claude.json"
    p.write_text(
        '{"projects": {"/repo": {"mcpServers": {"n": {"command": "npx", '
        '"args": ["-y", "@modelcontextprotocl/x@1.0.0"]}}}}}',
        encoding="utf-8",
    )
    assert "REGISTRY001" in _rule_ids(audit_paths([p]).findings)
