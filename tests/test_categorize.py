"""Tests for ``agentguard.categorize`` — Phase 1 path → category stub.

Phase 3 replaces this with ``pathspec``-based glob matching; for Phase 1
the implementation only distinguishes ``instruction`` (CLAUDE.md /
AGENTS.md, case-insensitive) from ``code`` (everything else).
"""

from __future__ import annotations

from pathlib import Path

from agentguard.categorize import categorize


def test_claude_md_is_instruction() -> None:
    assert categorize(Path("CLAUDE.md")) == "instruction"


def test_agents_md_is_instruction() -> None:
    assert categorize(Path("AGENTS.md")) == "instruction"


def test_lowercase_claude_md_is_instruction() -> None:
    assert categorize(Path("claude.md")) == "instruction"


def test_lowercase_agents_md_is_instruction() -> None:
    assert categorize(Path("agents.md")) == "instruction"


def test_subdir_claude_md_is_instruction() -> None:
    """Plan B3 — ``path.name.lower()`` only; no glob trickery needed."""
    assert categorize(Path("subdir/CLAUDE.md")) == "instruction"


def test_python_file_is_code() -> None:
    assert categorize(Path("module.py")) == "code"


def test_unknown_extension_is_code() -> None:
    assert categorize(Path("data.bin")) == "code"
