
# =============================================================================
# Script  : Lenovo-DriverReboot-Detection.ps1
# Purpose : Detect Lenovo driver updates (delivered via Intune WUfB driver
#           policy) that completed successfully but require a restart
# Output  : Restart Pending (Yes/No), Driver Name, Driver Version
# Sources : Windows Update history (COM), WU registry keys, WU event log,
#           Windows Driver Store
# Usage   : Run locally, via Nexthink Remote Action, or Intune Proactive
#           Remediation (detection script)
# =============================================================================

# ── Initialise result object ──────────────────────────────────────────────────
$result = [PSCustomObject]@{
    DeviceName        = $env:COMPUTERNAME
    Manufacturer      = ""
    RestartPending    = "No"
    DriverName        = "N/A"
    DriverVersion     = "N/A"
    DriverDate        = "N/A"
    DetectionSource   = "N/A"
    InstallTime       = "N/A"
}

# ── Step 1 : Confirm this is a Lenovo device ─────────────────────────────────
try {
    $manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
    $result.Manufacturer = $manufacturer

    if ($manufacturer -notlike "*Lenovo*") {
        Write-Output "========================================"
        Write-Output " Lenovo Driver Reboot Detection Report"
        Write-Output "========================================"
        Write-Output "Device Name      : $($result.DeviceName)"
        Write-Output "Manufacturer     : $manufacturer"
        Write-Output "Result           : SKIPPED - Not a Lenovo device"
        Write-Output "========================================"
        Write-Output "NXT_RestartPending=No"
        Write-Output "NXT_DriverName=N/A"
        Write-Output "NXT_DriverVersion=N/A"
        Write-Output "NXT_DetectionSource=Not a Lenovo device"
        Write-Output "NXT_InstallTime=N/A"
        exit 0
    }
}
catch {
    $result.Manufacturer = "Unknown"
}

# ── Step 2 : Check WU RebootRequired registry key (primary reboot signal) ─────
# This key is created exclusively by Windows Update when a driver or update
# requires a restart. Most reliable signal for WUfB-delivered drivers.
$wuRebootKey     = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
$wuRebootPending = Test-Path $wuRebootKey

if ($wuRebootPending) {
    $result.RestartPending  = "Yes"
    $result.DetectionSource = "WU-RebootRequired-Registry"
}

# ── Step 3 : Secondary registry reboot signals ────────────────────────────────
$rebootSources = @()

# CBS (Component Based Servicing) — driver INF processing pending
$cbs = Get-ItemProperty `
       "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing" `
       -ErrorAction SilentlyContinue
if ($cbs.RebootPending) {
    $rebootSources += "CBS-RebootPending"
}

# Session Manager — driver .sys/.dll file replacement queued until next boot
$sm = Get-ItemProperty `
      "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
      -ErrorAction SilentlyContinue
if ($sm.PendingFileRenameOperations) {
    $rebootSources += "PendingFileRenameOperations"
}

# Windows Update secondary reboot flag
$wuReboot2 = Get-ItemProperty `
             "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" `
             -ErrorAction SilentlyContinue
if ($wuReboot2.RebootRequired -eq 1) {
    $rebootSources += "WU-AutoUpdate-RebootRequired"
}

if ($rebootSources.Count -gt 0) {
    $result.RestartPending = "Yes"
    if ($result.DetectionSource -eq "N/A") {
        $result.DetectionSource = $rebootSources -join " | "
    }
    else {
        $result.DetectionSource += " | " + ($rebootSources -join " | ")
    }
}

# ── Step 4 : Windows Update history — get driver name + version ───────────────
# WU records every driver it installs via the COM update history object.
# ResultCode 2 = Succeeded. Looks for the most recent Lenovo driver
# installed within the last 14 days.
if ($result.RestartPending -eq "Yes") {
    try {
        $updateSession  = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $historyCount   = $updateSearcher.GetTotalHistoryCount()

        if ($historyCount -gt 0) {
            $history = $updateSearcher.QueryHistory(0, [Math]::Min($historyCount, 100))
            $cutoff  = (Get-Date).AddDays(-14)

            # Filter: succeeded, Lenovo-related, within last 14 days
            $lenovoDriverUpdate = $history | Where-Object {
                $_.ResultCode -eq 2 -and
                $_.Date       -ge $cutoff -and
                (
                    $_.Title       -match "(?i)lenovo" -or
                    $_.Description -match "(?i)lenovo"
                )
            } | Sort-Object Date -Descending | Select-Object -First 1

            if ($lenovoDriverUpdate) {
                $result.DriverName      = $lenovoDriverUpdate.Title
                $result.InstallTime     = $lenovoDriverUpdate.Date.ToString("yyyy-MM-dd HH:mm:ss")
                $result.DetectionSource += " | WU-Update-History"

                # Extract version from title if embedded (e.g. "Lenovo Audio Driver 1.0.3.2")
                $versionMatch = [regex]::Match($lenovoDriverUpdate.Title, '\d+\.\d+\.\d+\.\d+')
                if ($versionMatch.Success) {
                    $result.DriverVersion = $versionMatch.Value
                }
            }
        }
    }
    catch {
        $result.DetectionSource += " | WU-History-Error: $($_.Exception.Message)"
    }
}

# ── Step 5 : Windows Update event log — confirm via Event ID 19 / 43 ──────────
# Event ID 19 = update/driver installed successfully
# Event ID 43 = driver installation triggered a pending reboot
if ($result.RestartPending -eq "Yes") {
    try {
        $cutoff = (Get-Date).AddDays(-14)

        $driverEvents = Get-WinEvent `
                        -LogName "Microsoft-Windows-WindowsUpdateClient/Operational" `
                        -ErrorAction SilentlyContinue |
                        Where-Object {
                            $_.Id          -in @(19, 43) -and
                            $_.TimeCreated -ge $cutoff   -and
                            $_.Message     -match "(?i)lenovo|(?i)driver"
                        } |
                        Sort-Object TimeCreated -Descending |
                        Select-Object -First 1

        if ($driverEvents) {
            $result.DetectionSource += " | WU-EventLog(ID:$($driverEvents.Id))"

            # If driver name still not resolved, extract from event message
            if ($result.DriverName -eq "N/A") {
                $titleMatch = [regex]::Match($driverEvents.Message, '(?i)update\s+title[:\s]+(.+)')
                if ($titleMatch.Success) {
                    $result.DriverName  = $titleMatch.Groups[1].Value.Trim()
                    $result.InstallTime = $driverEvents.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                }
            }
        }

        # System log Event ID 20 — WU reboot required notification
        $systemRebootEvent = Get-WinEvent -LogName "System" -ErrorAction SilentlyContinue |
                             Where-Object {
                                 $_.Id           -eq 20 -and
                                 $_.TimeCreated  -ge $cutoff -and
                                 $_.ProviderName -match "(?i)WindowsUpdateClient"
                             } |
                             Sort-Object TimeCreated -Descending |
                             Select-Object -First 1

        if ($systemRebootEvent) {
            $result.DetectionSource += " | System-EventLog(ID:20)"
        }
    }
    catch {
        $result.DetectionSource += " | EventLog-ReadError"
    }
}

# ── Step 6 : Windows Driver Store — enrich name + version if still unknown ────
# Last resort: query the OS driver store for the most recently installed
# Lenovo driver. Gives driver name, version, and date directly from the OS.
if ($result.RestartPending -eq "Yes" -and $result.DriverName -eq "N/A") {
    try {
        $lenovoDriver = Get-WindowsDriver -Online -ErrorAction SilentlyContinue |
                        Where-Object { $_.ProviderName -like "*Lenovo*" } |
                        Sort-Object Date -Descending |
                        Select-Object -First 1

        if ($lenovoDriver) {
            $result.DriverName    = if ($lenovoDriver.OriginalFileName) {
                                        Split-Path $lenovoDriver.OriginalFileName -Leaf
                                    }
                                    else {
                                        $lenovoDriver.Driver
                                    }
            $result.DriverVersion = $lenovoDriver.Version
            $result.DriverDate    = if ($lenovoDriver.Date) {
                                        $lenovoDriver.Date.ToString("yyyy-MM-dd")
                                    }
                                    else { "N/A" }
            $result.DetectionSource += " | DriverStore-Enriched"
        }
    }
    catch {
        $result.DetectionSource += " | DriverStore-ReadError"
    }
}

# ── Step 7 : Output formatted report ──────────────────────────────────────────
Write-Output ""
Write-Output "========================================"
Write-Output " Lenovo Driver Reboot Detection Report"
Write-Output "========================================"
Write-Output "Device Name       : $($result.DeviceName)"
Write-Output "Manufacturer      : $($result.Manufacturer)"
Write-Output "Restart Pending   : $($result.RestartPending)"

if ($result.RestartPending -eq "Yes") {
    Write-Output "Driver Name       : $($result.DriverName)"
    Write-Output "Driver Version    : $($result.DriverVersion)"
    Write-Output "Driver Date       : $($result.DriverDate)"
    Write-Output "Install Time      : $($result.InstallTime)"
    Write-Output "Detection Source  : $($result.DetectionSource)"
}
else {
    Write-Output "Result            : No Lenovo driver restart pending detected"
}

Write-Output "========================================"
Write-Output ""

# ── Step 8 : Nexthink Remote Action output variables ──────────────────────────
# Map these as output variables in the Nexthink Remote Action definition
Write-Output "NXT_RestartPending=$($result.RestartPending)"
Write-Output "NXT_DriverName=$($result.DriverName)"
Write-Output "NXT_DriverVersion=$($result.DriverVersion)"
Write-Output "NXT_DriverDate=$($result.DriverDate)"
Write-Output "NXT_DetectionSource=$($result.DetectionSource)"
Write-Output "NXT_InstallTime=$($result.InstallTime)"

# ── Exit codes for Intune Proactive Remediation ────────────────────────────────
# Exit 1 = Restart pending detected (non-compliant — triggers remediation)
# Exit 0 = No restart pending        (compliant)
if ($result.RestartPending -eq "Yes") { exit 1 } else { exit 0 }
