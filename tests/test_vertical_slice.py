"""End-to-end vertical-slice tests for AgentGuard Phase 1 (OVR001 only).

These tests exercise the full pipeline: encoded poisoned fixture →
``materialize`` → ``categorize`` → ``scan_path`` → ``Span``-shaped findings →
``agentguard scan`` CLI exit code.

This module is **expected to be red** until Phase 1 Task 1.6 (user-generated
fixture), Task 1.7 (categorize), Task 1.8 (regex_engine), Task 1.9
(``agentguard.scan`` programmatic entry point), and Task 1.10 (``scan``
subcommand) all land.
"""

from __future__ import annotations

import base64
import hashlib

from click.testing import CliRunner

# N1 — smoke import: keep the helpers module import-tested even when no
# direct call site happens to exercise it in this file.
from tests.fixtures._helpers import inspect, materialize  # noqa: F401

# Will fail at collection time until Task 1.6 (user generates the fixture).
from tests.fixtures.poisoned import ovr001_basic

from agentguard.cli import main
from agentguard.scan import scan_path  # programmatic entry point — added in 1.9


def _round_trip_check() -> None:
    """B1 — verify the fixture's full-payload SHA + length round-trip."""
    decoded = base64.b64decode(ovr001_basic.PAYLOAD_B64)
    assert hashlib.sha256(decoded).hexdigest() == ovr001_basic.EXPECTED_PAYLOAD_SHA256
    assert len(decoded) == ovr001_basic.EXPECTED_PAYLOAD_LEN


def test_ovr001_in_instruction_category(tmp_path) -> None:
    _round_trip_check()
    path = materialize(ovr001_basic, tmp_path, filename="CLAUDE.md")
    findings = scan_path(path)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == ovr001_basic.EXPECTED["rule_id"]
    assert f.severity == ovr001_basic.EXPECTED["category_severity"]["instruction"]
    assert (
        hashlib.sha256(f.matched_text.encode("utf-8")).hexdigest()
        == ovr001_basic.EXPECTED_MATCH_SHA256
    )
    assert len(f.matched_text.encode("utf-8")) == ovr001_basic.EXPECTED_MATCH_LEN


def test_ovr001_in_code_category(tmp_path) -> None:
    _round_trip_check()
    path = materialize(ovr001_basic, tmp_path, filename="module.py")
    findings = scan_path(path)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == ovr001_basic.EXPECTED["category_severity"]["code"]
    assert (
        hashlib.sha256(f.matched_text.encode("utf-8")).hexdigest()
        == ovr001_basic.EXPECTED_MATCH_SHA256
    )


def test_exit_code_zero_when_no_block(tmp_path) -> None:
    """OVR001 in instruction/code categories is warn/silent — never block in
    Phase 1's two categories — so ``agentguard scan`` exits 0."""
    path = materialize(ovr001_basic, tmp_path, filename="CLAUDE.md")
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(path)])
    assert result.exit_code == 0
