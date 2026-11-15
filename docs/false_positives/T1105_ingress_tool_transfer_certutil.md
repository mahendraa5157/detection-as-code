# False Positives — Ingress Tool Transfer Via Certutil Or Bitsadmin Download

**Technique:** [T1105](https://attack.mitre.org/techniques/T1105/) &nbsp;|&nbsp; **Tactic:** Command And Control &nbsp;|&nbsp; **Severity:** high
**Rule:** `rules/windows/process_creation/T1105_ingress_tool_transfer_certutil.yml`
**Confidence:** High

## What legitimate activity can trigger this

- certutil used by scripts for legitimate certificate retrieval over HTTP (uncommon).

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

certutil pulling an executable from a URL, or bitsadmin /transfer, is rarely legitimate; hashfile/encode usages are excluded by requiring a URL.

## Validation

- **Atomic Red Team test:** certutil download
- **Example command:** `certutil -urlcache -f http://.../file`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
