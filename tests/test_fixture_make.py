"""Tests for ``agentguard fixture-make``.

Uses an inline ``TEST001`` rule (not a real OVR/MCP/MEM/UNI rule) so test
payloads are innocuous English strings against ``(?i)\\bhello\\b``. This keeps
prompt-injection prose out of the test source code.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import sys
from pathlib import Path
from types import ModuleType

import click
import pytest
from click.testing import CliRunner

from agentguard.cli import main
from agentguard.config import Config, Rule
from agentguard.tools.fixture_make import _compute_constants, run


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


def _import_emitted(path: Path, name: str) -> ModuleType:
    """Import a generated fixture module from an arbitrary file path."""
    sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_emitted_module_exports_required_names(tmp_path: Path) -> None:
    out = tmp_path / "fx_exports.py"
    run(
        "TEST001",
        out,
        payload_source=io.StringIO("hello world from the test"),
        cfg=_test_config(),
    )

    mod = _import_emitted(out, "fx_exports")
    for attr in (
        "PAYLOAD_B64",
        "EXPECTED_PAYLOAD_SHA256",
        "EXPECTED_PAYLOAD_LEN",
        "EXPECTED_MATCH_SHA256",
        "EXPECTED_MATCH_LEN",
        "EXPECTED",
    ):
        assert hasattr(mod, attr), f"emitted module missing {attr!r}"


def test_payload_round_trip(tmp_path: Path) -> None:
    payload = "hello world from the test"
    out = tmp_path / "fx_round_trip.py"
    run("TEST001", out, payload_source=io.StringIO(payload), cfg=_test_config())

    mod = _import_emitted(out, "fx_round_trip")
    decoded = base64.b64decode(mod.PAYLOAD_B64)
    assert decoded == payload.encode("utf-8")
    assert hashlib.sha256(decoded).hexdigest() == mod.EXPECTED_PAYLOAD_SHA256
    assert len(decoded) == mod.EXPECTED_PAYLOAD_LEN


def test_match_constants_describe_regex_match(tmp_path: Path) -> None:
    payload = "Hello world from the test"  # regex hits "Hello"
    out = tmp_path / "fx_match.py"
    run("TEST001", out, payload_source=io.StringIO(payload), cfg=_test_config())

    mod = _import_emitted(out, "fx_match")
    expected_match = "Hello"
    assert (
        hashlib.sha256(expected_match.encode("utf-8")).hexdigest()
        == mod.EXPECTED_MATCH_SHA256
    )
    assert len(expected_match.encode("utf-8")) == mod.EXPECTED_MATCH_LEN
    # Match SHA must differ from full-payload SHA (B1 fix).
    assert mod.EXPECTED_MATCH_SHA256 != mod.EXPECTED_PAYLOAD_SHA256
    assert mod.EXPECTED_MATCH_LEN != mod.EXPECTED_PAYLOAD_LEN


def test_expected_dict_carries_full_severity_matrix(tmp_path: Path) -> None:
    out = tmp_path / "fx_expected.py"
    run(
        "TEST001",
        out,
        payload_source=io.StringIO("hello"),
        cfg=_test_config(),
    )

    mod = _import_emitted(out, "fx_expected")
    assert mod.EXPECTED["rule_id"] == "TEST001"
    assert mod.EXPECTED["category_severity"] == {
        "instruction": "warn",
        "code": "silent",
    }


def test_self_verifies_round_trip(tmp_path: Path) -> None:
    """Tool re-decodes its own emitted output and confirms the hash is consistent."""
    out = tmp_path / "fx_self.py"
    run(
        "TEST001",
        out,
        payload_source=io.StringIO("hello self-check"),
        cfg=_test_config(),
    )

    mod = _import_emitted(out, "fx_self")
    decoded = base64.b64decode(mod.PAYLOAD_B64)
    assert hashlib.sha256(decoded).hexdigest() == mod.EXPECTED_PAYLOAD_SHA256


def test_rejects_payload_that_does_not_match_regex(tmp_path: Path) -> None:
    out = tmp_path / "fx_nomatch.py"
    with pytest.raises(click.ClickException):
        run(
            "TEST001",
            out,
            payload_source=io.StringIO("goodbye world"),
            cfg=_test_config(),
        )
    assert not out.exists()


def test_rejects_non_ascii_payload_by_default(tmp_path: Path) -> None:
    out = tmp_path / "fx_unicode.py"
    with pytest.raises(click.ClickException):
        run(
            "TEST001",
            out,
            payload_source=io.StringIO("héllo world"),
            cfg=_test_config(),
        )
    assert not out.exists()


def test_unknown_rule_id_raises(tmp_path: Path) -> None:
    out = tmp_path / "fx_unknown.py"
    with pytest.raises(KeyError):
        run(
            "DOES_NOT_EXIST",
            out,
            payload_source=io.StringIO("hello"),
            cfg=_test_config(),
        )


def test_summary_output_does_not_contain_payload(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Tool must print only lengths + hashes, never the decoded payload."""
    out = tmp_path / "fx_summary.py"
    run(
        "TEST001",
        out,
        payload_source=io.StringIO("hello canary-string"),
        cfg=_test_config(),
    )
    captured = capsys.readouterr()
    assert "canary-string" not in captured.out
    assert "canary-string" not in captured.err


def test_strips_trailing_newline_from_stdin(tmp_path: Path) -> None:
    out = tmp_path / "fx_newline.py"
    run(
        "TEST001",
        out,
        payload_source=io.StringIO("hello world\n"),
        cfg=_test_config(),
    )
    mod = _import_emitted(out, "fx_newline")
    assert base64.b64decode(mod.PAYLOAD_B64) == b"hello world"


def test_cli_subcommand_round_trip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sanity check: ``agentguard fixture-make`` wires through to ``run()``."""
    monkeypatch.setattr(
        "agentguard.tools.fixture_make.load_config", _test_config
    )
    out = tmp_path / "fx_cli.py"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["fixture-make", "--rule", "TEST001", "--out", str(out)],
        input="hello world\n",
    )
    assert result.exit_code == 0, result.output
    assert out.exists()

    mod = _import_emitted(out, "fx_cli")
    assert base64.b64decode(mod.PAYLOAD_B64) == b"hello world"
    assert mod.EXPECTED["rule_id"] == "TEST001"


def test_rejects_payload_with_embedded_nul(tmp_path: Path) -> None:
    """ASCII-mode validation must reject NUL and other C0 control chars (R2)."""
    out = tmp_path / "fx_nul.py"
    with pytest.raises(click.ClickException):
        run(
            "TEST001",
            out,
            payload_source=io.StringIO("hello\x00world"),
            cfg=_test_config(),
        )
    assert not out.exists()


def test_emitted_category_severity_keys_sorted(tmp_path: Path) -> None:
    """Sorted keys at emit time keep regenerated-fixture diffs stable (R3).

    Also pins that ``_compute_constants`` enforces ``str`` keys and values for
    ``category_severity`` — a future enum-typed severity would otherwise emit
    invalid Python.
    """
    out = tmp_path / "fx_sorted.py"
    run(
        "TEST001",
        out,
        payload_source=io.StringIO("hello"),
        cfg=_test_config(),
    )
    text = out.read_text(encoding="utf-8")
    # _test_config has insertion order {"instruction": ..., "code": ...}.
    # After sort, 'code' must appear before 'instruction' in emitted source.
    assert text.index("'code'") < text.index("'instruction'")

    bad_rule = Rule(
        id="BAD001",
        name="bad",
        pattern=r"x",
        default_severity="warn",
        category_severity={"instruction": "warn"},
    )
    object.__setattr__(bad_rule, "category_severity", {"instruction": 123})
    with pytest.raises(AssertionError):
        _compute_constants("payload", None, bad_rule)


def test_no_match_error_does_not_leak_payload_to_stderr_or_exception(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Error path on regex-no-match must not echo payload content (R4)."""
    out = tmp_path / "fx_nomatch_canary.py"
    canary = "supersecret-canary-12345"
    payload = f"goodbye world {canary}"
    with pytest.raises(click.ClickException) as excinfo:
        run(
            "TEST001",
            out,
            payload_source=io.StringIO(payload),
            cfg=_test_config(),
        )
    assert canary not in str(excinfo.value)
    assert canary not in (excinfo.value.message or "")
    captured = capsys.readouterr()
    assert canary not in captured.out
    assert canary not in captured.err
    assert not out.exists()


class _TtyStringIO(io.StringIO):
    """StringIO that lies about being a TTY — exercises the interactive prompt branch."""

    def isatty(self) -> bool:  # pragma: no cover - trivial override
        return True


def test_prints_prompt_when_source_is_tty(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Interactive runs must print the documented stdin-prompt to stderr.

    Spec doc ``tests/fixtures/_specs/ovr001_basic.spec.md`` promises the tool
    prompts the user before blocking on ``stdin.read()`` — otherwise the tool
    looks hung in PowerShell. This test pins the visible-prompt behavior.
    """
    out = tmp_path / "fx_tty_prompt.py"
    src = _TtyStringIO("hello world from a tty\n")
    run("TEST001", out, payload_source=src, cfg=_test_config())
    captured = capsys.readouterr()
    assert "Enter payload" in captured.err


def test_no_prompt_when_source_is_not_tty(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Piped / scripted runs (CliRunner, ``echo ... |``) must NOT print the prompt.

    Plain ``io.StringIO`` reports ``isatty() == False``; the prompt branch
    must short-circuit so structured callers don't see stray prose on stderr.
    """
    out = tmp_path / "fx_notty_no_prompt.py"
    run(
        "TEST001",
        out,
        payload_source=io.StringIO("hello world\n"),
        cfg=_test_config(),
    )
    captured = capsys.readouterr()
    assert "Enter payload" not in captured.err
