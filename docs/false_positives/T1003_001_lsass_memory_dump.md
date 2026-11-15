# False Positives — LSASS Memory Dump Via Comsvcs Or Procdump

**Technique:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/) &nbsp;|&nbsp; **Tactic:** Credential Access &nbsp;|&nbsp; **Severity:** high
**Rule:** `rules/windows/process_creation/T1003_001_lsass_memory_dump.yml`
**Confidence:** High

## What legitimate activity can trigger this

- Sysadmins intentionally dumping LSASS for crash analysis with procdump (rare, should be ticketed).

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

comsvcs MiniDump against LSASS has essentially no legitimate use on endpoints; procdump -ma lsass is nearly always an incident.

## Validation

- **Atomic Red Team test:** comsvcs MiniDump
- **Example command:** `rundll32 comsvcs.dll, MiniDump <pid> dump.bin full`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
