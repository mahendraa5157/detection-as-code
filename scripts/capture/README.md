# Lab capture workflow

How the sample logs under `tests/sample_*_logs/` are produced and validated against a
real Windows 10 + Sysmon VM.

## Lab setup (one-time)

- Windows 10 VM (VirtualBox) with a snapshot named something like
  **"clean sysmon + atomic red team"** to revert to between runs.
- [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) installed with a
  good config (SwiftOnSecurity or olafhartong). Verify:
  `Get-Service sysmon*` and events in `Microsoft-Windows-Sysmon/Operational`.
- [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam):
  ```powershell
  Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force
  Install-AtomicRedTeam -getAtomics
  ```

## Capture loop (per technique)

1. **Revert** the VM to the clean baseline snapshot (host):
   ```bash
   VBoxManage snapshot "windows 10" restore "clean sysmon + atomic red team"
   VBoxManage startvm "windows 10"
   ```
2. **Run** the capture script inside the VM (elevated PowerShell):
   ```powershell
   .\scripts\capture\Capture-AtomicLogs.ps1 -Techniques T1003.001
   ```
   It runs the mapped atomic, exports the Sysmon events it generated, and cleans up.
3. **Sanitize** the exported JSON (replace real hostnames/SIDs with lab placeholders),
   keep the single event that represents the detection, set `"_provenance":
   "real-capture"`, and save it as `tests/sample_malicious_logs/<rule_id>_malicious.json`.
4. **Benign lookalike**: hand-craft the paired `tests/sample_benign_logs/<rule_id>_benign.json`
   — the closest legitimate command that must NOT fire the rule.
5. `python -m pytest tests/ -q` must stay green.

## Why both a host snapshot and `-Cleanup`

Reverting the snapshot guarantees a pristine state for clean captures; `Invoke-AtomicTest
-Cleanup` is a best-effort fast path when you run several techniques in one boot. For the
rules in this repo the Sysmon command-line fields are deterministic, so synthetic samples
authored from the atomic's documented command line match real captures field-for-field —
which is why the suite is meaningful even before every sample is swapped to `real-capture`.
