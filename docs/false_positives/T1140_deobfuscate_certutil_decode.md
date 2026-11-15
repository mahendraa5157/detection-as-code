# False Positives — Deobfuscate/Decode Files Via Certutil Decode

**Technique:** [T1140](https://attack.mitre.org/techniques/T1140/) &nbsp;|&nbsp; **Tactic:** Defense Evasion &nbsp;|&nbsp; **Severity:** medium
**Rule:** `rules/windows/process_creation/T1140_deobfuscate_certutil_decode.yml`
**Confidence:** Medium

## What legitimate activity can trigger this

- Rare legitimate certificate workflows that base64-decode files.

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

certutil decoding to an executable is a common staging step; benign certificate decoding exists but is uncommon on endpoints.

## Validation

- **Atomic Red Team test:** certutil decode
- **Example command:** `certutil -decode enc.txt out.exe`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
