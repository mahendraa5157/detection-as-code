# False Positives — Local Account Creation Via Net User

**Technique:** [T1136.001](https://attack.mitre.org/techniques/T1136/001/) &nbsp;|&nbsp; **Tactic:** Persistence &nbsp;|&nbsp; **Severity:** medium
**Rule:** `rules/windows/process_creation/T1136_001_create_local_account.yml`
**Confidence:** Medium

## What legitimate activity can trigger this

- Provisioning scripts that create service or local admin accounts.

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

Account creation is legitimate during provisioning; pair with off-hours or unusual-host context to raise confidence.

## Validation

- **Atomic Red Team test:** Create local user
- **Example command:** `net user <name> <pass> /add`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
