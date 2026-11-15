# False Positives — Process Discovery Via Tasklist Or Get-Process

**Technique:** [T1057](https://attack.mitre.org/techniques/T1057/) &nbsp;|&nbsp; **Tactic:** Discovery &nbsp;|&nbsp; **Severity:** low
**Rule:** `rules/windows/process_creation/T1057_process_discovery.yml`
**Confidence:** Low

## What legitimate activity can trigger this

- Monitoring agents and admin scripts that enumerate processes regularly.

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

Process listing is ubiquitous in management tooling; useful as part of a discovery cluster, not as a standalone high-severity alert.

## Validation

- **Atomic Red Team test:** Process discovery
- **Example command:** `tasklist /v`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
