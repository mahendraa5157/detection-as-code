# False Positives — Persistence Via Registry Run Key Modification

**Technique:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/) &nbsp;|&nbsp; **Tactic:** Persistence &nbsp;|&nbsp; **Severity:** medium
**Rule:** `rules/windows/registry_set/T1547_001_registry_run_key.yml`
**Confidence:** Medium

## What legitimate activity can trigger this

- Legitimate applications installing autostart entries from their install directory (excluded by requiring suspicious paths).

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

Run-key writes are common at install time; restricting to user-writable/temp paths and script interpreters removes most vendor noise while catching staged payloads.

## Validation

- **Atomic Red Team test:** Run key persistence
- **Example command:** `reg add HKCU\...\Run /v ... /d <payload>`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
