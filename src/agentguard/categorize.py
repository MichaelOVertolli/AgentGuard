"""Path → file-category mapping (Phase 1 stub).

Phase 1 only distinguishes ``instruction`` (CLAUDE.md / AGENTS.md,
case-insensitive, by basename only) from ``code`` (everything else). Phase 3
replaces this with ``pathspec``-based glob matching driven by ``policy.toml``;
Phase 1 deliberately avoids the policy-loading machinery (decision D1).

Plan note B3: ``path.match("**/CLAUDE.md")`` is dead code on Python 3.12 (it
matches against the full path, not the basename), so this module relies on
``path.name.lower()`` only.
"""

from __future__ import annotations

from pathlib import Path


def categorize(path: Path) -> str:
    if path.name.lower() in ("claude.md", "agents.md"):
        return "instruction"
    return "code"
