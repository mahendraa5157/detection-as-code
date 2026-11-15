# False Positives — Mshta Execution Of Remote Or Inline Script

**Technique:** [T1218.005](https://attack.mitre.org/techniques/T1218/005/) &nbsp;|&nbsp; **Tactic:** Defense Evasion &nbsp;|&nbsp; **Severity:** high
**Rule:** `rules/windows/process_creation/T1218_005_mshta_execution.yml`
**Confidence:** High

## What legitimate activity can trigger this

- Legacy line-of-business apps delivered as signed local .hta files.

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

mshta reaching out to a URL or running inline script is a strong indicator; local signed HTAs are the only notable benign case.

## Validation

- **Atomic Red Team test:** mshta remote
- **Example command:** `mshta vbscript:...http://.../a.sct`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
