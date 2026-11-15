# False Positives — UAC Bypass Via Fodhelper Registry Hijack

**Technique:** [T1548.002](https://attack.mitre.org/techniques/T1548/002/) &nbsp;|&nbsp; **Tactic:** Privilege Escalation &nbsp;|&nbsp; **Severity:** high
**Rule:** `rules/windows/process_creation/T1548_002_uac_bypass_fodhelper.yml`
**Confidence:** High

## What legitimate activity can trigger this

- Normal fodhelper usage spawns SystemSettings-related processes, which are filtered out.

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

fodhelper spawning cmd/powershell instead of SystemSettings is a reliable UAC-bypass indicator; the filter removes its normal child processes.

## Validation

- **Atomic Red Team test:** fodhelper UAC bypass
- **Example command:** `fodhelper.exe (after ms-settings hijack)`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
