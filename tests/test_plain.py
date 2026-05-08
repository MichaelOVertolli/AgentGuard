"""Tests for ``agentguard.output.plain.to_plain`` — Phase 1 plain renderer.

Phase 6 polishes visuals. Phase 1 only needs to: render rule_id + line:col +
severity tier + truncated snippet, group by file (header once per file),
and tag block / warn / silent visually with rich markup.
"""

from __future__ import annotations

from pathlib import Path

from agentguard.detectors.regex_engine import Span
from agentguard.output.plain import to_plain


def _span(
    *,
    rule_id: str = "TEST001",
    line: int = 1,
    col: int = 1,
    end_line: int = 1,
    end_col: int = 6,
    snippet: str = "hello world",
    severity: str = "warn",
    matched_text: str = "hello",
) -> Span:
    return Span(
        rule_id=rule_id,
        line=line,
        col=col,
        end_line=end_line,
        end_col=end_col,
        snippet=snippet,
        severity=severity,
        matched_text=matched_text,
    )


def test_to_plain_empty_findings_returns_empty_string() -> None:
    assert to_plain([]) == ""


def test_to_plain_includes_rule_id_path_and_line_col() -> None:
    out = to_plain([(Path("CLAUDE.md"), "instruction", _span(line=2, col=15))])
    assert "TEST001" in out
    assert "CLAUDE.md" in out
    assert "2:15" in out


def test_to_plain_marks_warn_severity() -> None:
    out = to_plain([(Path("CLAUDE.md"), "instruction", _span(severity="warn"))])
    assert "WARN" in out


def test_to_plain_marks_block_severity() -> None:
    out = to_plain([(Path("plan.md"), "plan", _span(severity="block"))])
    assert "BLOCK" in out


def test_to_plain_marks_silent_severity() -> None:
    out = to_plain([(Path("module.py"), "code", _span(severity="silent"))])
    # Silent renders dimmer; use lowercase marker so it visually de-emphasizes.
    assert "silent" in out


def test_to_plain_truncates_long_snippet() -> None:
    long = "x" * 200
    out = to_plain([(Path("CLAUDE.md"), "instruction", _span(snippet=long))])
    assert "x" * 200 not in out


def test_to_plain_does_not_repeat_file_path_on_every_finding() -> None:
    """Plan §"output": group by file — file path is the section header, not
    repeated on each finding line."""
    out = to_plain(
        [
            (Path("uniquepath.md"), "instruction", _span(rule_id="AAA")),
            (Path("uniquepath.md"), "instruction", _span(rule_id="BBB", line=2)),
        ]
    )
    assert "AAA" in out
    assert "BBB" in out
    assert out.count("uniquepath.md") == 1
