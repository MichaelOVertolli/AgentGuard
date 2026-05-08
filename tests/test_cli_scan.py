"""Tests for the ``agentguard scan`` CLI subcommand.

The vertical-slice test exercises the warn/silent path on the OVR001 fixture
(exit code 0). These tests pin the gaps:

* exit code 1 when any finding is severity=block
* ``--config`` overrides the bundled corpus
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from click.testing import CliRunner

from agentguard.cli import main


_TEST001_BLOCK_RULES = textwrap.dedent(
    """
    [[rules]]
    id = "TEST001"
    name = "hello-block"
    pattern = '(?i)\\bhello\\b'
    default_severity = "block"
    category_severity = { instruction = "block", code = "block" }
    """
).strip()

_TEST001_WARN_RULES = textwrap.dedent(
    """
    [[rules]]
    id = "TEST001"
    name = "hello-warn"
    pattern = '(?i)\\bhello\\b'
    default_severity = "warn"
    category_severity = { instruction = "warn", code = "silent" }
    """
).strip()


def test_scan_exit_code_one_when_finding_is_block(tmp_path: Path) -> None:
    rules = tmp_path / "rules.toml"
    rules.write_text(_TEST001_BLOCK_RULES, encoding="utf-8")
    target = tmp_path / "CLAUDE.md"
    target.write_text("the line says hello inside it", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        main, ["scan", "--config", str(rules), str(target)]
    )
    assert result.exit_code == 1


def test_scan_exit_code_zero_when_findings_are_warn_only(tmp_path: Path) -> None:
    rules = tmp_path / "rules.toml"
    rules.write_text(_TEST001_WARN_RULES, encoding="utf-8")
    target = tmp_path / "CLAUDE.md"
    target.write_text("the line says hello inside it", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        main, ["scan", "--config", str(rules), str(target)]
    )
    assert result.exit_code == 0


def test_scan_config_flag_overrides_bundled_corpus(tmp_path: Path) -> None:
    """Custom rule with no OVR001-shape match shouldn't false-positive on the
    bundled corpus's OVR001 rule because ``--config`` swaps the rule pack."""
    rules = tmp_path / "rules.toml"
    rules.write_text(_TEST001_WARN_RULES, encoding="utf-8")
    target = tmp_path / "CLAUDE.md"
    target.write_text("nothing matching anything in this prose", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        main, ["scan", "--config", str(rules), str(target)]
    )
    assert result.exit_code == 0
    # Output is empty / no rule_id present
    assert "TEST001" not in result.output
