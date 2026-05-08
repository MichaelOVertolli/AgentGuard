"""Tests for ``agentguard.scan.scan_path`` — programmatic entry point used by
the CLI scan subcommand and directly by tests.

Uses the same TEST001 inline rule pattern as ``test_regex_engine.py`` /
``test_fixture_make.py`` to keep injection-shaped strings out of the test
source. The OVR001-fixture path is exercised end-to-end in
``test_vertical_slice.py``.
"""

from __future__ import annotations

from pathlib import Path

from agentguard.config import Config, Rule
from agentguard.scan import scan_path


def _hello_config() -> Config:
    return Config(
        rules=(
            Rule(
                id="TEST001",
                name="hello-test",
                pattern=r"(?i)\bhello\b",
                default_severity="warn",
                category_severity={"instruction": "warn", "code": "silent"},
            ),
        )
    )


def test_scan_path_returns_empty_for_clean_file(tmp_path: Path) -> None:
    p = tmp_path / "clean.md"
    p.write_text("just prose with nothing matching", encoding="utf-8")
    assert scan_path(p, _hello_config()) == []


def test_scan_path_returns_span_when_match_present(tmp_path: Path) -> None:
    p = tmp_path / "CLAUDE.md"
    p.write_text("the line says hello", encoding="utf-8")
    findings = scan_path(p, _hello_config())
    assert len(findings) == 1
    assert findings[0].rule_id == "TEST001"
    assert findings[0].matched_text == "hello"


def test_scan_path_categorizes_via_filename_for_severity(tmp_path: Path) -> None:
    """``scan_path`` calls ``categorize`` on the path; CLAUDE.md → instruction → warn."""
    p = tmp_path / "CLAUDE.md"
    p.write_text("hello inside", encoding="utf-8")
    findings = scan_path(p, _hello_config())
    assert findings[0].severity == "warn"


def test_scan_path_silents_in_code_category(tmp_path: Path) -> None:
    p = tmp_path / "module.py"
    p.write_text("def hello(): pass", encoding="utf-8")
    findings = scan_path(p, _hello_config())
    assert len(findings) == 1
    assert findings[0].severity == "silent"


def test_scan_path_with_default_cfg_loads_bundled_corpus(tmp_path: Path) -> None:
    """When ``cfg`` is ``None``, ``scan_path`` calls ``load_config()`` for the
    bundled OVR001 corpus. Use a clean file so we don't smuggle OVR001 prose
    into the test source — clean input produces no findings, which is enough
    to confirm the default-config code path runs end-to-end."""
    p = tmp_path / "clean.md"
    p.write_text("plain prose with no rule matches", encoding="utf-8")
    assert scan_path(p) == []
