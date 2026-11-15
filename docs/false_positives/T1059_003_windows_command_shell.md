# False Positives — Suspicious Windows Command Shell Child Of Office Application

**Technique:** [T1059.003](https://attack.mitre.org/techniques/T1059/003/) &nbsp;|&nbsp; **Tactic:** Execution &nbsp;|&nbsp; **Severity:** medium
**Rule:** `rules/windows/process_creation/T1059_003_windows_command_shell.yml`
**Confidence:** High

## What legitimate activity can trigger this

- Office add-ins or templates that legitimately shell out for document automation.

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

Office applications spawning cmd.exe is almost never legitimate end-user behaviour; parent/child lineage makes this low-noise.

## Validation

- **Atomic Red Team test:** Macro spawns cmd
- **Example command:** `cmd.exe /c <payload>`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
