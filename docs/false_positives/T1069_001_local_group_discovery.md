# False Positives — Local Permission Group Discovery

**Technique:** [T1069.001](https://attack.mitre.org/techniques/T1069/001/) &nbsp;|&nbsp; **Tactic:** Discovery &nbsp;|&nbsp; **Severity:** low
**Rule:** `rules/windows/process_creation/T1069_001_local_group_discovery.yml`
**Confidence:** Low

## What legitimate activity can trigger this

- Admin scripts auditing group membership.

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

Group enumeration is common in administration; the /add filter ensures membership modification is handled elsewhere. Benign sample is a group-modify command the discovery rule intentionally ignores.

## Validation

- **Atomic Red Team test:** Group discovery
- **Example command:** `net localgroup administrators`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
