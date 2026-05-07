"""Hand-rolled loader for AgentGuard's rule pack.

Phase 1 loads ``corpus/detector_rules.toml`` only. ``policy.toml`` is introduced
in Phase 3. ``[engine]`` configuration is introduced in the phase that first
needs it (per Phase 1 plan, fix D2).
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Literal

Severity = Literal["block", "warn", "silent"]
_VALID_SEVERITIES: frozenset[str] = frozenset({"block", "warn", "silent"})


class ConfigError(ValueError):
    """Raised when ``detector_rules.toml`` fails schema validation."""


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    pattern: str
    default_severity: Severity
    category_severity: dict[str, Severity]

    def severity_for(self, category: str) -> Severity:
        return self.category_severity.get(category, self.default_severity)


@dataclass(frozen=True)
class Config:
    rules: tuple[Rule, ...]

    def rule_by_id(self, rule_id: str) -> Rule:
        for r in self.rules:
            if r.id == rule_id:
                return r
        raise KeyError(
            f"Unknown rule_id: {rule_id!r}. Known: {[r.id for r in self.rules]}"
        )


def _validate_severity(rule_id: str, key: str, value: object) -> Severity:
    if value not in _VALID_SEVERITIES:
        raise ConfigError(
            f"Rule {rule_id!r}: {key} must be one of "
            f"{sorted(_VALID_SEVERITIES)}, got {value!r}"
        )
    return value  # type: ignore[return-value]


def _build_rule(raw: dict[str, object]) -> Rule:
    try:
        rule_id = raw["id"]
        name = raw["name"]
        pattern = raw["pattern"]
        default_severity = raw["default_severity"]
    except KeyError as exc:
        raise ConfigError(f"Rule missing required field: {exc.args[0]!r}") from exc
    if not isinstance(rule_id, str):
        raise ConfigError(f"Rule id must be a string, got {type(rule_id).__name__}")

    default_severity = _validate_severity(rule_id, "default_severity", default_severity)

    raw_cat = raw.get("category_severity", {})
    if not isinstance(raw_cat, dict):
        raise ConfigError(
            f"Rule {rule_id!r}: category_severity must be a table"
        )
    category_severity: dict[str, Severity] = {}
    for cat, sev in raw_cat.items():
        category_severity[cat] = _validate_severity(
            rule_id, f"category_severity[{cat!r}]", sev
        )

    return Rule(
        id=rule_id,
        name=name,  # type: ignore[arg-type]
        pattern=pattern,  # type: ignore[arg-type]
        default_severity=default_severity,
        category_severity=category_severity,
    )


def load_config(rules_path: Path | None = None) -> Config:
    """Load rules from ``rules_path`` or the bundled ``corpus/detector_rules.toml``."""
    if rules_path is None:
        data = (files("agentguard.corpus") / "detector_rules.toml").read_bytes()
    else:
        data = Path(rules_path).read_bytes()

    parsed = tomllib.loads(data.decode("utf-8"))
    raw_rules = parsed.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ConfigError("Top-level 'rules' must be an array of tables")

    return Config(rules=tuple(_build_rule(r) for r in raw_rules))
