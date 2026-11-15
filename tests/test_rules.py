"""Rule logic tests.

For every Sigma rule under rules/ this suite asserts:
  1. the rule fires on its malicious sample log, and
  2. the rule does NOT fire on its benign lookalike.

Matching is done offline with tests/sigma_eval.py (pySigma parses the rule;
we evaluate the parsed condition tree against sample events), so no live
SIEM is required in CI. Sample logs live in tests/sample_*_logs/ and are named
after the rule file id.
"""
import json
from pathlib import Path

import pytest

from tests.sigma_eval import load_rule, rule_matches

REPO = Path(__file__).resolve().parent.parent
RULES = sorted((REPO / "rules").rglob("*.yml"))
MAL = REPO / "tests" / "sample_malicious_logs"
BEN = REPO / "tests" / "sample_benign_logs"


def _ids(rules):
    return [r.stem for r in rules]


def _load_event(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("rule_path", RULES, ids=_ids(RULES))
def test_rule_fires_on_malicious(rule_path):
    fid = rule_path.stem
    sample = MAL / f"{fid}_malicious.json"
    assert sample.exists(), f"missing malicious sample for {fid}"
    rule = load_rule(rule_path)
    assert rule_matches(rule, _load_event(sample)) is True, (
        f"{fid} did not fire on its malicious sample"
    )


@pytest.mark.parametrize("rule_path", RULES, ids=_ids(RULES))
def test_rule_silent_on_benign(rule_path):
    fid = rule_path.stem
    sample = BEN / f"{fid}_benign.json"
    assert sample.exists(), f"missing benign sample for {fid}"
    rule = load_rule(rule_path)
    assert rule_matches(rule, _load_event(sample)) is False, (
        f"{fid} false-positived on its benign lookalike"
    )


def test_at_least_25_rules():
    assert len(RULES) >= 25, f"expected >=25 rules, found {len(RULES)}"
