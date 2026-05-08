"""Phase 1 regex detector — converts ``(text, Config, category)`` into a list of
``Span`` findings.

Uses the third-party ``regex`` library rather than stdlib ``re`` so rule
patterns can rely on Unicode character classes and lookbehind constructs
without the Python-version constraints stdlib ``re`` imposes. Per plan D1.4,
silents are returned in the result list (not filtered); the renderer is
responsible for visual treatment.

Per plan note S3, line/col arithmetic uses *character* offsets, not byte
offsets — multi-byte UTF-8 sequences would otherwise mis-locate matches.
``match.start()`` / ``match.end()`` from ``regex`` are character offsets, so
the bisect over ``_compute_line_starts`` resolves them correctly.
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass

import regex as re

from agentguard.config import Config


@dataclass(frozen=True)
class Span:
    rule_id: str
    line: int
    col: int
    end_line: int
    end_col: int
    snippet: str
    severity: str
    matched_text: str


def scan_regex(text: str, cfg: Config, category: str) -> list[Span]:
    line_starts = _compute_line_starts(text)
    lines = text.splitlines()
    spans: list[Span] = []
    for rule in cfg.rules:
        compiled = re.compile(rule.pattern)
        severity = rule.severity_for(category)
        for match in compiled.finditer(text):
            start_line, start_col = _offset_to_lc(match.start(), line_starts)
            end_line, end_col = _offset_to_lc(match.end(), line_starts)
            snippet = lines[start_line - 1] if 0 <= start_line - 1 < len(lines) else ""
            spans.append(
                Span(
                    rule_id=rule.id,
                    line=start_line,
                    col=start_col,
                    end_line=end_line,
                    end_col=end_col,
                    snippet=snippet,
                    severity=severity,
                    matched_text=match.group(0),
                )
            )
    return spans


def _compute_line_starts(text: str) -> list[int]:
    """Character offsets at which each line begins. Line 1 starts at offset 0."""
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def _offset_to_lc(offset: int, line_starts: list[int]) -> tuple[int, int]:
    """Convert a 0-indexed character offset to (line, col), both 1-indexed.

    ``end_col`` semantics are exclusive — when called with ``match.end()``,
    the returned column is one past the last matched character (SARIF-style).
    """
    line_index = bisect.bisect_right(line_starts, offset) - 1
    col = offset - line_starts[line_index] + 1
    return line_index + 1, col
