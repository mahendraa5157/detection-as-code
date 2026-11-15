# False Positives — System Owner/User Discovery Via Whoami

**Technique:** [T1033](https://attack.mitre.org/techniques/T1033/) &nbsp;|&nbsp; **Tactic:** Discovery &nbsp;|&nbsp; **Severity:** low
**Rule:** `rules/windows/process_creation/T1033_system_owner_user_discovery.yml`
**Confidence:** Low

## What legitimate activity can trigger this

- Admins and support staff verifying identity and privileges.
- Login scripts that log the current user context.

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

Plain whoami is ubiquitous, so the rule requires enumeration flags (/all, /groups, /priv). Still low severity; value comes from clustering with other discovery.

## Validation

- **Atomic Red Team test:** Whoami discovery
- **Example command:** `whoami /all`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
