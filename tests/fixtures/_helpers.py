"""Helpers for working with encoded poisoned-fixture modules.

Fixtures under ``tests/fixtures/poisoned/`` store payloads as base64 constants
so they remain inert in any reader's context (IDE-opened files, stack traces,
git diffs). These helpers are the only sanctioned paths to a decoded payload.

Two entry points:

* :func:`materialize` — decode a fixture's payload to a temp file under pytest.
* :func:`inspect` — decode to a string for human review **only**. Never call
  from automation; never paste the return value into agent conversations or
  commit messages; never chain it into a tool that surfaces stdout to a model
  context.

Greppable call site by design — ``inspect(`` outside of a manual REPL or
notebook is a bug.
"""

from __future__ import annotations

import base64
from pathlib import Path
from types import ModuleType


def materialize(
    fixture_module: ModuleType,
    tmp_path: Path,
    filename: str = "fixture.md",
) -> Path:
    """Decode a fixture's payload to a temp file for pytest. Caller owns cleanup."""
    p = tmp_path / filename
    p.write_bytes(base64.b64decode(fixture_module.PAYLOAD_B64))
    return p


def inspect(fixture_module: ModuleType) -> str:
    """Decode a fixture's payload to a string for HUMAN review only.

    Use when authoring or reviewing a fixture file. Do not call from automation,
    do not paste the return value into agent conversations or commit messages,
    and do not chain this into any tool that surfaces stdout to a model context.

    Equivalent CLI (manual, ad hoc)::

        python -c "from tests.fixtures._helpers import inspect; \\
                   from tests.fixtures.poisoned import <name>; print(inspect(<name>))"
    """
    return base64.b64decode(fixture_module.PAYLOAD_B64).decode("utf-8", errors="replace")
