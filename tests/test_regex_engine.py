"""Tests for ``agentguard.detectors.regex_engine`` — converts ``(text, rule)``
pairs into ``Span`` findings.

Uses an inline ``TEST001`` rule pattern ``(?i)\\bhello\\b`` so the test source
itself stays free of injection-shaped strings. Severity matrix mirrors
OVR001's shape (instruction=warn, code=silent) so behavior under D1.4 (silents
are first-class, returned not filtered) is exercised.
"""

from __future__ import annotations

from agentguard.config import Config, Rule
from agentguard.detectors.regex_engine import Span, scan_regex


def _test_config() -> Config:
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


def test_returns_empty_list_when_no_match() -> None:
    assert scan_regex("nothing to see here", _test_config(), "instruction") == []


def test_returns_empty_list_for_empty_text() -> None:
    assert scan_regex("", _test_config(), "instruction") == []


def test_single_match_returns_one_span_with_correct_shape() -> None:
    text = "this line says hello inside it"
    findings = scan_regex(text, _test_config(), "instruction")
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, Span)
    assert f.rule_id == "TEST001"
    assert f.matched_text == "hello"
    assert f.severity == "warn"


def test_line_and_col_are_one_indexed_on_first_line() -> None:
    """``"this line says "`` is 15 chars; ``"hello"`` starts at col 16."""
    text = "this line says hello inside it"
    findings = scan_regex(text, _test_config(), "instruction")
    f = findings[0]
    assert f.line == 1
    assert f.col == 16


def test_match_on_later_line_reports_correct_line_and_col() -> None:
    text = "line one has nothing\nline two says hello\nline three nothing"
    findings = scan_regex(text, _test_config(), "instruction")
    assert len(findings) == 1
    f = findings[0]
    assert f.line == 2
    # "line two says " is 14 chars on line 2; "hello" starts at col 15
    assert f.col == 15


def test_end_col_is_exclusive_one_past_last_char() -> None:
    """``end_col`` is the column AFTER the final matched character (SARIF-style)."""
    text = "hello world"
    findings = scan_regex(text, _test_config(), "instruction")
    f = findings[0]
    assert f.col == 1
    assert f.end_line == 1
    # "hello" is 5 chars long, started at col 1, so end_col is 6
    assert f.end_col == 6
    assert f.end_col - f.col == len(f.matched_text)


def test_silent_severity_is_returned_not_filtered() -> None:
    """Plan D1.4 — silents are first-class in the engine output."""
    findings = scan_regex("def hello(): pass", _test_config(), "code")
    assert len(findings) == 1
    assert findings[0].severity == "silent"


def test_unknown_category_falls_back_to_rule_default_severity() -> None:
    findings = scan_regex("hello world", _test_config(), "not_a_real_category")
    assert len(findings) == 1
    assert findings[0].severity == "warn"  # default_severity in _test_config


def test_multiple_matches_yield_multiple_spans() -> None:
    text = "hello first\nthen hello again\nand hello once more"
    findings = scan_regex(text, _test_config(), "instruction")
    assert len(findings) == 3
    assert [f.line for f in findings] == [1, 2, 3]
    assert all(f.matched_text == "hello" for f in findings)


def test_case_insensitive_match_preserves_input_casing_in_matched_text() -> None:
    findings = scan_regex("HELLO World", _test_config(), "instruction")
    assert len(findings) == 1
    assert findings[0].matched_text == "HELLO"


def test_snippet_contains_the_matching_line_content() -> None:
    text = "first line\nthe word hello is on line two\nthird line"
    findings = scan_regex(text, _test_config(), "instruction")
    assert len(findings) == 1
    assert "the word hello is on line two" in findings[0].snippet
