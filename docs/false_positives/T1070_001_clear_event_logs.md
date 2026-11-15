# False Positives — Windows Event Log Cleared Via Wevtutil Or PowerShell

**Technique:** [T1070.001](https://attack.mitre.org/techniques/T1070/001/) &nbsp;|&nbsp; **Tactic:** Defense Evasion &nbsp;|&nbsp; **Severity:** high
**Rule:** `rules/windows/process_creation/T1070_001_clear_event_logs.yml`
**Confidence:** High

## What legitimate activity can trigger this

- Log rotation or forensic cleanup scripts in test environments (should be rare on production).

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

Clearing the Security log is a classic anti-forensics step; query operations are excluded by matching only the clear verbs.

## Validation

- **Atomic Red Team test:** Clear logs
- **Example command:** `wevtutil cl Security`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
