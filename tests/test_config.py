"""Tests for ``agentguard.config`` — the hand-rolled rule-pack loader."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from agentguard.config import Config, ConfigError, Rule, load_config


def test_default_config_loads_ovr001() -> None:
    cfg = load_config()
    assert isinstance(cfg, Config)
    rule = cfg.rule_by_id("OVR001")
    assert isinstance(rule, Rule)
    assert rule.name == "ignore-previous-instructions"


def test_ovr001_severity_for_instruction_is_warn() -> None:
    cfg = load_config()
    assert cfg.rule_by_id("OVR001").severity_for("instruction") == "warn"


def test_ovr001_severity_for_code_is_silent() -> None:
    cfg = load_config()
    assert cfg.rule_by_id("OVR001").severity_for("code") == "silent"


def test_ovr001_severity_for_unknown_category_falls_back_to_default() -> None:
    cfg = load_config()
    rule = cfg.rule_by_id("OVR001")
    assert rule.default_severity == "warn"
    assert rule.severity_for("not_a_real_category") == "warn"


def test_rule_by_id_raises_on_unknown_rule() -> None:
    cfg = load_config()
    with pytest.raises(KeyError):
        cfg.rule_by_id("DOES_NOT_EXIST")


def test_load_config_validates_severity_values(tmp_path: Path) -> None:
    bad = tmp_path / "bad.toml"
    bad.write_text(
        textwrap.dedent(
            """
            [[rules]]
            id = "BAD001"
            name = "bad-severity"
            pattern = "x"
            default_severity = "explode"
            category_severity = { instruction = "warn" }
            """
        ).strip(),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_config(bad)


def test_load_config_validates_category_severity_values(tmp_path: Path) -> None:
    bad = tmp_path / "bad.toml"
    bad.write_text(
        textwrap.dedent(
            """
            [[rules]]
            id = "BAD002"
            name = "bad-category-severity"
            pattern = "x"
            default_severity = "warn"
            category_severity = { instruction = "explode" }
            """
        ).strip(),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_config(bad)
