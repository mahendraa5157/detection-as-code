# False Positives — Rundll32 Proxy Execution Of Suspicious Payloads

**Technique:** [T1218.011](https://attack.mitre.org/techniques/T1218/011/) &nbsp;|&nbsp; **Tactic:** Defense Evasion &nbsp;|&nbsp; **Severity:** medium
**Rule:** `rules/windows/process_creation/T1218_011_rundll32_proxy_exec.yml`
**Confidence:** Medium

## What legitimate activity can trigger this

- Rare installers that stage DLLs in %TEMP% and invoke them via rundll32.

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

rundll32 is heavily used by Windows; the suspicious-argument gate (javascript:, temp/appdata paths, URLs) cuts most benign calls but staging installers can still match.

## Validation

- **Atomic Red Team test:** rundll32 JS
- **Example command:** `rundll32 javascript:...RunHTMLApplication`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
