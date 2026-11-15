# False Positives — System Network Configuration Discovery

**Technique:** [T1016](https://attack.mitre.org/techniques/T1016/) &nbsp;|&nbsp; **Tactic:** Discovery &nbsp;|&nbsp; **Severity:** low
**Rule:** `rules/windows/process_creation/T1016_system_network_config_discovery.yml`
**Confidence:** Low

## What legitimate activity can trigger this

- Routine troubleshooting by help desk and users.
- Login scripts that log network configuration.

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

These commands are extremely common in normal troubleshooting; valuable only when correlated into a sequence of discovery commands, hence low severity on its own.

## Validation

- **Atomic Red Team test:** Network discovery
- **Example command:** `ipconfig /all; arp -a; route print`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
