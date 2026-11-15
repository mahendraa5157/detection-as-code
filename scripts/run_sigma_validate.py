"""Validate every Sigma rule for structure, required metadata, and backend compile.

Fails (exit 1) if any rule:
  * does not parse as a Sigma rule,
  * is missing required metadata (level, falsepositives, references, an
    attack.txxxx tag, a tactic tag), or
  * does not compile to the Elasticsearch (Lucene) backend.

Run: python scripts/run_sigma_validate.py
This is the gate CI uses to reject under-documented rules.
"""
from __future__ import annotations

import sys
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule

try:
    from sigma.backends.elasticsearch.elasticsearch_lucene import LuceneBackend
    HAVE_BACKEND = True
except Exception:  # pragma: no cover
    HAVE_BACKEND = False

REPO = Path(__file__).resolve().parent.parent
RULES = sorted((REPO / "rules").rglob("*.yml"))

REQUIRED_LEVELS = {"informational", "low", "medium", "high", "critical"}


def check_rule(path: Path) -> list[str]:
    errs: list[str] = []
    text = path.read_text(encoding="utf-8")
    try:
        rule = SigmaRule.from_yaml(text)
    except Exception as e:  # noqa: BLE001
        return [f"does not parse: {e}"]

    if rule.level is None or rule.level.name.lower() not in REQUIRED_LEVELS:
        errs.append("missing or invalid 'level'")
    if not rule.falsepositives:
        errs.append("missing 'falsepositives'")
    if not rule.references:
        errs.append("missing 'references'")

    tags = {str(t) for t in rule.tags}
    if not any(t.startswith("attack.t") for t in tags):
        errs.append("missing an 'attack.txxxx' technique tag")
    tactic_tags = {
        "attack.execution", "attack.persistence", "attack.privilege_escalation",
        "attack.defense_evasion", "attack.credential_access", "attack.discovery",
        "attack.lateral_movement", "attack.collection", "attack.command_and_control",
        "attack.exfiltration", "attack.impact", "attack.initial_access",
        "attack.reconnaissance", "attack.resource_development",
    }
    if not (tags & tactic_tags):
        errs.append("missing a tactic tag (e.g. attack.execution)")

    if HAVE_BACKEND:
        try:
            LuceneBackend().convert(SigmaCollection([rule]))
        except Exception as e:  # noqa: BLE001
            errs.append(f"does not compile to elasticsearch-lucene: {e}")
    return errs


def main() -> int:
    if not RULES:
        print("No rules found under rules/", file=sys.stderr)
        return 1
    failed = 0
    for path in RULES:
        rel = path.relative_to(REPO)
        errs = check_rule(path)
        if errs:
            failed += 1
            print(f"[FAIL] {rel}")
            for e in errs:
                print(f"        - {e}")
        else:
            print(f"[ OK ] {rel}")
    print("-" * 60)
    print(f"{len(RULES)} rules, {failed} failed"
          + ("" if HAVE_BACKEND else "  (elasticsearch backend not installed; compile step skipped)"))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
