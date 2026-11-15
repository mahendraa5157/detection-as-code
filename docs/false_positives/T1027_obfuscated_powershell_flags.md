# False Positives — Obfuscated PowerShell Via Stacked Evasion Flags

**Technique:** [T1027](https://attack.mitre.org/techniques/T1027/) &nbsp;|&nbsp; **Tactic:** Defense Evasion &nbsp;|&nbsp; **Severity:** medium
**Rule:** `rules/windows/process_creation/T1027_obfuscated_powershell_flags.yml`
**Confidence:** Medium

## What legitimate activity can trigger this

- Some legitimate deployment tools run hidden with bypass policy; validate the script source.

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

The combination of hidden window AND execution-policy bypass is far more suspicious than either alone, but packaged deployment tools occasionally use both.

## Validation

- **Atomic Red Team test:** Obfuscated flags
- **Example command:** `powershell -w hidden -ep bypass -enc ...`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
