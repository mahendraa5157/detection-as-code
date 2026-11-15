"""Minimal offline Sigma rule evaluator for unit tests.

pySigma parses the rule (modifiers, condition grammar, wildcards); this module
walks the parsed condition tree and evaluates it against a flat JSON event.
Matching follows Sigma semantics: case-insensitive string matching, list
values OR'd, fields within a selection AND'd.
"""
from __future__ import annotations

import re
from pathlib import Path

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import SigmaNull, SigmaNumber, SigmaRegularExpression, SigmaString, SigmaCIDRExpression


def load_rule(path: str | Path) -> SigmaRule:
    return SigmaRule.from_yaml(Path(path).read_text(encoding="utf-8"))


def _get_field(event: dict, field: str):
    if field in event:
        return event[field]
    # case-insensitive fallback
    lower = {k.lower(): v for k, v in event.items()}
    return lower.get(field.lower())


def _match_value(value, actual) -> bool:
    if isinstance(value, SigmaNull):
        return actual is None
    if actual is None:
        return False
    if isinstance(actual, list):
        return any(_match_value(value, a) for a in actual)
    if isinstance(value, SigmaString):
        rx = str(value.to_regex().regexp)
        return re.fullmatch(rx, str(actual), re.IGNORECASE | re.DOTALL) is not None
    if isinstance(value, SigmaRegularExpression):
        flags = 0
        for f in getattr(value, "flags", set()) or set():
            flags |= {"i": re.I, "m": re.M, "s": re.S}.get(getattr(f, "value", str(f))[0].lower(), 0)
        return re.search(value.regexp, str(actual), flags) is not None
    if isinstance(value, SigmaNumber):
        try:
            return float(actual) == float(value.number)
        except (TypeError, ValueError):
            return str(actual) == str(value.number)
    if isinstance(value, SigmaCIDRExpression):
        import ipaddress
        try:
            return ipaddress.ip_address(str(actual)) in value.network
        except ValueError:
            return False
    raise NotImplementedError(f"Unsupported value type {type(value).__name__}")


def _eval(node, event: dict) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval(a, event) for a in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _match_value(node.value, _get_field(event, node.field))
    if isinstance(node, ConditionValueExpression):  # keyword search over all fields
        return any(_match_value(node.value, v) for v in event.values() if isinstance(v, (str, int)))
    raise NotImplementedError(f"Unsupported condition node {type(node).__name__}")


def rule_matches(rule: SigmaRule, event: dict) -> bool:
    return any(_eval(cond.parse(), event) for cond in rule.detection.parsed_condition)
