# False Positives — Scheduled Task Creation Via Schtasks

**Technique:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/) &nbsp;|&nbsp; **Tactic:** Persistence &nbsp;|&nbsp; **Severity:** medium
**Rule:** `rules/windows/process_creation/T1053_005_scheduled_task_creation.yml`
**Confidence:** Medium

## What legitimate activity can trigger this

- Legitimate software installers (Chrome, Edge, OneDrive) registering update tasks.
- IT automation creating maintenance jobs.

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

Task creation is common on endpoints; the filter removes the noisiest vendor updaters but bespoke admin jobs remain a source of benign hits, hence medium.

## Validation

- **Atomic Red Team test:** Scheduled task persistence
- **Example command:** `schtasks /create /tn ... /tr ...`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
