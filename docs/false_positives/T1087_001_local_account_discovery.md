# False Positives — Local Account Discovery Via Net User

**Technique:** [T1087.001](https://attack.mitre.org/techniques/T1087/001/) &nbsp;|&nbsp; **Tactic:** Discovery &nbsp;|&nbsp; **Severity:** low
**Rule:** `rules/windows/process_creation/T1087_001_local_account_discovery.yml`
**Confidence:** Low

## What legitimate activity can trigger this

- Admins checking account state.
- Login scripts that query account policy.

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

Account enumeration is routine for admins; the /add exclusion keeps this separate from the persistence rule. Low on its own.

## Validation

- **Atomic Red Team test:** Account discovery
- **Example command:** `net user`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
