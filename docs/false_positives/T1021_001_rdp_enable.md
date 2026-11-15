# False Positives — Remote Desktop Enabled Via Registry From Command Line

**Technique:** [T1021.001](https://attack.mitre.org/techniques/T1021/001/) &nbsp;|&nbsp; **Tactic:** Lateral Movement &nbsp;|&nbsp; **Severity:** medium
**Rule:** `rules/windows/process_creation/T1021_001_rdp_enable.yml`
**Confidence:** Medium

## What legitimate activity can trigger this

- IT enabling RDP during provisioning via a configuration script.

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

Enabling RDP is legitimate during provisioning; correlate with the user/host context. Medium because sanctioned admin provisioning looks identical.

## Validation

- **Atomic Red Team test:** Enable RDP
- **Example command:** `reg add ... fDenyTSConnections /d 0`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
