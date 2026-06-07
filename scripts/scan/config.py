"""Per-repo configuration loading.

A repo can drop a `.synup-scan.json` at its root to tune the scan, e.g.:

    {
      "disable": ["dangerous_code"],          // turn off whole checks
      "min_severity": "high",                 // override default blocking threshold
      "allow": ["test/fixtures/**", "docs/*"],// glob paths to skip entirely
      "secrets":        { "disable_rules": ["jwt", "stripe_publishable"] },
      "dangerous_code": { "disable_rules": ["weak_hash"] }
    }

Everything is optional. No file = all checks on, defaults applied.
Inline, suppress a single line by adding a `synup-ignore` comment to it.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    disable: set[str] = field(default_factory=set)        # check names to skip
    min_severity: str | None = None                       # overrides CLI default if set
    allow: list[str] = field(default_factory=list)        # path globs to skip
    per_check: dict[str, dict] = field(default_factory=dict)  # e.g. {"secrets": {"disable_rules": [...]}}

    def disabled_rules(self, check: str) -> set[str]:
        return set(self.per_check.get(check, {}).get("disable_rules", []))

    @classmethod
    def load(cls, path: Path | None) -> "Config":
        if not path or not path.is_file():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return cls()
        known = {"disable", "min_severity", "allow"}
        per_check = {k: v for k, v in data.items() if k not in known and isinstance(v, dict)}
        return cls(
            disable=set(data.get("disable", []) or []),
            min_severity=data.get("min_severity"),
            allow=list(data.get("allow", []) or []),
            per_check=per_check,
        )

    @staticmethod
    def discover(start: Path) -> Path | None:
        """Look for .synup-scan.json in `start` (the repo root / CWD)."""
        cand = start / ".synup-scan.json"
        return cand if cand.is_file() else None
