"""AgentGuard command-line entry point."""

from __future__ import annotations

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


if __name__ == "__main__":
    main()
