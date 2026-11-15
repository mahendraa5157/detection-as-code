<#
.SYNOPSIS
    Runs the Atomic Red Team tests mapped in emulation/ and exports the triggering
    Sysmon events as JSON, ready to drop into tests/sample_malicious_logs/.

.DESCRIPTION
    Intended to run INSIDE the Windows 10 lab VM (elevated PowerShell) that has:
      * Sysmon installed and logging (SwiftOnSecurity / olafhartong config), and
      * Invoke-AtomicRedTeam + the atomics folder installed.

    Workflow per the repo's emulation loop:
      1. Revert the VM to the clean Sysmon + Atomic baseline snapshot (from the host).
      2. Run this script. For each technique it records a time marker, runs the mapped
         atomic, then exports Sysmon events (EID 1/13) created after the marker.
      3. Copy the generated JSON out via the shared folder, sanitize host-specific
         fields, set "_provenance": "real-capture", and commit.

    This script only READS the atomic mapping and RUNS atomics you already installed in
    your own lab. It makes no network calls of its own. Review each atomic before running;
    some download test payloads or modify the system (that is the point of the VM snapshot).

.PARAMETER OutDir
    Where to write exported JSON. Default: .\captured_logs

.PARAMETER Techniques
    Optional list of technique IDs to run (e.g. T1003.001). Default: all in emulation/.

.EXAMPLE
    .\Capture-AtomicLogs.ps1 -Techniques T1003.001,T1059.001
#>
[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path $PSScriptRoot "captured_logs"),
    [string[]]$Techniques
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$emulationDir = Join-Path $repoRoot "emulation"

if (-not (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue)) {
    Write-Warning "Invoke-AtomicTest not found. Install with: Install-Module -Name invoke-atomicredteam -Scope CurrentUser"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$sysmonLog = "Microsoft-Windows-Sysmon/Operational"

function Export-SysmonSince($marker, $path) {
    # Pull EID 1 (process create) and 13 (registry set) since the marker, flatten to JSON.
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = $sysmonLog
        Id        = @(1, 13)
        StartTime = $marker
    } -ErrorAction SilentlyContinue

    $out = foreach ($e in $events) {
        $x = [xml]$e.ToXml()
        $d = @{}
        foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
        [pscustomobject]@{
            EventID     = [int]$e.Id
            UtcTime     = $d['UtcTime']
            Image       = $d['Image']
            CommandLine = $d['CommandLine']
            ParentImage = $d['ParentImage']
            User        = $d['User']
            TargetObject= $d['TargetObject']
            Details     = $d['Details']
            EventType   = $d['EventType']
            _provenance = "real-capture"
        }
    }
    $out | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 $path
    return ($out | Measure-Object).Count
}

$maps = Get-ChildItem -Path $emulationDir -Recurse -Filter atomic_test_mapping.yml
foreach ($map in $maps) {
    $tid = Split-Path $map.Directory -Leaf
    if ($Techniques -and ($tid -notin $Techniques)) { continue }

    Write-Host "`n=== $tid ===" -ForegroundColor Cyan
    $marker = (Get-Date).AddSeconds(-1)
    try {
        Invoke-AtomicTest $tid -ErrorAction Continue
        Start-Sleep -Seconds 3
        $dest = Join-Path $OutDir ("{0}_capture.json" -f ($tid -replace '\.', '_'))
        $n = Export-SysmonSince $marker $dest
        Write-Host "  exported $n event(s) -> $dest" -ForegroundColor Green
    }
    catch {
        Write-Warning "  $tid failed: $($_.Exception.Message)"
    }
    finally {
        Invoke-AtomicTest $tid -Cleanup -ErrorAction SilentlyContinue | Out-Null
    }
}

Write-Host "`nDone. Review JSON in $OutDir, sanitize, and copy matching events into tests/sample_malicious_logs/." -ForegroundColor Yellow
