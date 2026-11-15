# False Positives — System Information Discovery Via Systeminfo

**Technique:** [T1082](https://attack.mitre.org/techniques/T1082/) &nbsp;|&nbsp; **Tactic:** Discovery &nbsp;|&nbsp; **Severity:** low
**Rule:** `rules/windows/process_creation/T1082_system_information_discovery.yml`
**Confidence:** Low

## What legitimate activity can trigger this

- Inventory and asset-management tooling.
- Support staff gathering host details.

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

systeminfo is common in inventory scripts; only meaningful as part of broader hands-on-keyboard discovery.

## Validation

- **Atomic Red Team test:** System info
- **Example command:** `systeminfo`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
