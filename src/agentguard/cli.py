"""AgentGuard command-line entry point."""

from __future__ import annotations

import sys
from pathlib import Path

import click


@click.group()
def main() -> None:
    """AgentGuard — scan agent-adjacent files for prompt-injection patterns."""


@main.command(name="fixture-make")
@click.option("--rule", "rule_id", required=True, help="Rule ID, e.g. OVR001.")
@click.option(
    "--out",
    "out_path",
    required=True,
    type=click.Path(path_type=Path),
    help="Path to write the generated fixture module.",
)
@click.option(
    "--negative",
    is_flag=True,
    help="Phase 2+: regex must NOT match the payload.",
)
@click.option(
    "--allow-unicode",
    is_flag=True,
    help="Phase 2+: permit non-ASCII payloads (UNI* rules).",
)
def fixture_make_cmd(
    rule_id: str, out_path: Path, negative: bool, allow_unicode: bool
) -> None:
    """Build a poisoned-fixture module from a payload read on stdin."""
    from agentguard.tools.fixture_make import run

    run(rule_id, out_path, negative=negative, allow_unicode=allow_unicode)


@main.command()
@click.argument(
    "paths", nargs=-1, type=click.Path(exists=True, path_type=Path)
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Override the bundled rule pack with an external detector_rules.toml.",
)
def scan(paths: tuple[Path, ...], config_path: Path | None) -> None:
    """Scan one or more files for prompt-injection patterns."""
    from rich.console import Console

    from agentguard.categorize import categorize
    from agentguard.config import load_config
    from agentguard.output.plain import to_plain
    from agentguard.scan import scan_path

    cfg = load_config(config_path)
    all_findings: list[tuple[Path, str, object]] = []
    for f in paths:
        category = categorize(f)
        for span in scan_path(f, cfg):
            all_findings.append((f, category, span))

    rendered = to_plain(all_findings)  # type: ignore[arg-type]
    if rendered:
        Console().print(rendered)

    has_block = any(span.severity == "block" for _, _, span in all_findings)  # type: ignore[attr-defined]
    sys.exit(1 if has_block else 0)


if __name__ == "__main__":
    main()
