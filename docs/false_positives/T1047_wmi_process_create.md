# False Positives — WMI Process Creation Via Wmic

**Technique:** [T1047](https://attack.mitre.org/techniques/T1047/) &nbsp;|&nbsp; **Tactic:** Execution &nbsp;|&nbsp; **Severity:** medium
**Rule:** `rules/windows/process_creation/T1047_wmi_process_create.yml`
**Confidence:** Medium

## What legitimate activity can trigger this

- Legacy management scripts that launch processes through WMIC.

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

WMIC process creation appears in some admin scripts; the verb triple is specific but legitimate remote-exec tooling can still match.

## Validation

- **Atomic Red Team test:** wmic exec
- **Example command:** `wmic process call create "<cmd>"`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
