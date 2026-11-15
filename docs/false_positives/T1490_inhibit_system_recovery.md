# False Positives — Inhibit System Recovery Via Shadow Copy Deletion

**Technique:** [T1490](https://attack.mitre.org/techniques/T1490/) &nbsp;|&nbsp; **Tactic:** Impact &nbsp;|&nbsp; **Severity:** high
**Rule:** `rules/windows/process_creation/T1490_inhibit_system_recovery.yml`
**Confidence:** High

## What legitimate activity can trigger this

- Backup software that rotates shadow copies (verify against the known backup product).

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

Bulk shadow-copy deletion is a hallmark of ransomware; list/resize operations are excluded by requiring the delete verb.

## Validation

- **Atomic Red Team test:** Delete shadows
- **Example command:** `vssadmin delete shadows /all /quiet`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
