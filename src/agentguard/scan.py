"""Programmatic entry point for scanning a single file path.

Used directly by tests (``test_vertical_slice.py``, ``test_scan_path.py``)
and indirectly by the CLI ``scan`` subcommand. The CLI iterates paths and
calls this for each one, then renders the aggregated tuples through
``output.plain.to_plain``.
"""

from __future__ import annotations

from pathlib import Path

from agentguard.categorize import categorize
from agentguard.config import Config, load_config
from agentguard.detectors.regex_engine import Span, scan_regex


def scan_path(path: Path, cfg: Config | None = None) -> list[Span]:
    cfg = cfg if cfg is not None else load_config()
    text = path.read_text(encoding="utf-8")
    category = categorize(path)
    return scan_regex(text, cfg, category)
