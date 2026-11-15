# False Positives — Registry Tampering To Disable Security Controls

**Technique:** [T1112](https://attack.mitre.org/techniques/T1112/) &nbsp;|&nbsp; **Tactic:** Defense Evasion &nbsp;|&nbsp; **Severity:** high
**Rule:** `rules/windows/process_creation/T1112_modify_registry_disable_security.yml`
**Confidence:** High

## What legitimate activity can trigger this

- Hardening or imaging scripts that intentionally set these values (should be reviewed and allow-listed).

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

Disabling UAC/Defender/SmartScreen through the registry is high-impact; only sanctioned imaging/hardening should do this, and that should be allow-listed by host.

## Validation

- **Atomic Red Team test:** Disable UAC via registry
- **Example command:** `reg add ...\System /v EnableLUA /d 0 /f`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
