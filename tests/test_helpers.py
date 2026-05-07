"""Tests for ``tests.fixtures._helpers``.

Covers ``materialize`` and ``inspect``, the only sanctioned paths to a
decoded poisoned-fixture payload. Test fixtures here are constructed
in-memory (no real injection prose); they only need a ``PAYLOAD_B64``
attribute to satisfy the helpers' contract.
"""

from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace

from tests.fixtures._helpers import inspect, materialize


def _fake_fixture(payload: bytes) -> SimpleNamespace:
    return SimpleNamespace(PAYLOAD_B64=base64.b64encode(payload).decode("ascii"))


def test_materialize_writes_decoded_bytes_to_tmp_path(tmp_path: Path) -> None:
    payload = b"hello world"
    out = materialize(_fake_fixture(payload), tmp_path)
    assert out.read_bytes() == payload


def test_materialize_defaults_filename_to_fixture_md(tmp_path: Path) -> None:
    out = materialize(_fake_fixture(b"x"), tmp_path)
    assert out.name == "fixture.md"
    assert out.parent == tmp_path


def test_materialize_respects_filename_argument(tmp_path: Path) -> None:
    out = materialize(_fake_fixture(b"x"), tmp_path, filename="CLAUDE.md")
    assert out.name == "CLAUDE.md"
    assert out.read_bytes() == b"x"


def test_materialize_returns_path_pointing_at_file(tmp_path: Path) -> None:
    out = materialize(_fake_fixture(b"x"), tmp_path, filename="m.py")
    assert isinstance(out, Path)
    assert out.is_file()


def test_inspect_decodes_payload_to_string() -> None:
    payload_text = "hello world from inspect"
    fixture = _fake_fixture(payload_text.encode("utf-8"))
    assert inspect(fixture) == payload_text


def test_inspect_replaces_invalid_utf8_rather_than_raising() -> None:
    """`inspect` is a human-review affordance; broken bytes must not crash it."""
    fixture = _fake_fixture(b"\xff\xfe not utf-8")
    result = inspect(fixture)
    assert isinstance(result, str)
    assert "not utf-8" in result
