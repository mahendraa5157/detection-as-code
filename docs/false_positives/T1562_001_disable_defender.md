# False Positives — Impair Defenses - Disable Microsoft Defender

**Technique:** [T1562.001](https://attack.mitre.org/techniques/T1562/001/) &nbsp;|&nbsp; **Tactic:** Defense Evasion &nbsp;|&nbsp; **Severity:** high
**Rule:** `rules/windows/process_creation/T1562_001_disable_defender.yml`
**Confidence:** High

## What legitimate activity can trigger this

- Security teams adding sanctioned Defender exclusions during software rollout.

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

Turning off real-time monitoring is high-risk and should always be investigated; exclusion additions are tracked because attackers use them to whitelist payload paths.

## Validation

- **Atomic Red Team test:** Disable Defender
- **Example command:** `Set-MpPreference -DisableRealtimeMonitoring $true`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
