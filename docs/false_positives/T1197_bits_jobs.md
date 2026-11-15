# False Positives — BITS Job Used For Download Or Persistence

**Technique:** [T1197](https://attack.mitre.org/techniques/T1197/) &nbsp;|&nbsp; **Tactic:** Defense Evasion &nbsp;|&nbsp; **Severity:** medium
**Rule:** `rules/windows/process_creation/T1197_bits_jobs.yml`
**Confidence:** Medium

## What legitimate activity can trigger this

- Legitimate software updaters that use BITS (Windows Update, some installers).

## Suggested tuning

- Scope the rule to the user population and hosts where this behaviour is unexpected.
- Add explicit `filter_*` exclusions for your known-good tooling (service accounts, deployment agents, backup products) by parent process, user, or path.
- Where possible, correlate with surrounding events (parent process lineage, a burst of discovery commands) before escalating.

## Why this confidence level

BITS is legitimately used by updaters; the job-creation verbs narrow it but vendor update flows can still match, hence medium.

## Validation

- **Atomic Red Team test:** BITS job
- **Example command:** `bitsadmin /transfer ... http://...`
- Positive sample: `tests/sample_malicious_logs/` &nbsp;|&nbsp; Benign lookalike: `tests/sample_benign_logs/`
