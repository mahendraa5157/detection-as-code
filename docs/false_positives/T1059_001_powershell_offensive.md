# False Positives — PowerShell Execution Of Offensive Tooling Or Encoded Commands

**Technique:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/) &nbsp;|&nbsp; **Tactic:** Execution &nbsp;|&nbsp; **Severity:** high
**Rule:** `rules/windows/process_creation/T1059_001_powershell_offensive.yml`
**Confidence:** High

## What legitimate activity can trigger this

- Software deployment frameworks (SCCM, PDQ) that legitimately pass base64-encoded payloads.
- Administrators using Invoke-Expression with internal module repositories.

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

The offensive-module keywords and -EncodedCommand together are rarely both present in sanctioned automation; base64 payloads in interactive sessions are strong signal.

## Validation

- **Atomic Red Team test:** Mimikatz / Encoded command
- **Example command:** `powershell.exe -enc <base64>`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
