"""Phase 1 plain-text renderer (with rich markup) for scan findings.

Usage::

    text = to_plain([(path, category, span), ...])
    rich.print(text)  # or click.echo(text); rich markup degrades gracefully

Findings are grouped by file: each file gets a single bold-path header line
followed by one finding line per match. Severity tier renders as a colored
marker (block=red, warn=yellow, silent=dim) so a quick eyeball pass over
the output ranks issues. Snippets are truncated to 80 characters so a
long matched line doesn't blow up the terminal.

Phase 6 polishes layout, alignment, and adds SARIF / GitHub-annotation
output siblings; Phase 1 ships this usable-but-rough version per plan
Task 1.9.
"""

from __future__ import annotations

from pathlib import Path

from agentguard.detectors.regex_engine import Span

_SNIPPET_MAX = 80


def to_plain(findings: list[tuple[Path, str, Span]]) -> str:
    if not findings:
        return ""
    by_file: dict[Path, list[tuple[str, Span]]] = {}
    for path, category, span in findings:
        by_file.setdefault(path, []).append((category, span))
    lines: list[str] = []
    for path, items in by_file.items():
        lines.append(f"[bold]{path}[/bold]")
        for _, span in items:
            tier = _tier_marker(span.severity)
            snippet = _truncate(span.snippet, _SNIPPET_MAX)
            lines.append(
                f"  {span.line}:{span.col}  {tier}  {span.rule_id}  {snippet}"
            )
    return "\n".join(lines)


def _tier_marker(severity: str) -> str:
    if severity == "block":
        return "[bold red]BLOCK[/bold red]"
    if severity == "warn":
        return "[yellow]WARN[/yellow]"
    if severity == "silent":
        return "[dim]silent[/dim]"
    return severity


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"
