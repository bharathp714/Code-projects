# =============================================================================
# Script  : Lenovo-DriverReboot-Detection.ps1
# Purpose : Detect Lenovo driver updates (delivered via Intune WUfB driver
#           policy) that completed successfully but require a restart
# Output  : Restart Pending (Yes/No), Driver Name, Driver Version,
#           Driver Built Date, Actual Install Date on Device
# Sources : WU registry keys, WU history (COM), WU event log,
#           Windows Driver Store, Win32_PnPEntity, DriverStore folder date
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
    DriverBuiltDate   = "N/A"   # Date Lenovo authored/signed the driver package
    DriverInstallDate = "N/A"   # Date WU actually installed it on this device
    DetectionSource   = "N/A"
}

# ── Step 1 : Confirm this is a Lenovo device ─────────────────────────────────
try {
    $manufacturer        = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
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
        Write-Output "NXT_DriverBuiltDate=N/A"
        Write-Output "NXT_DriverInstallDate=N/A"
        Write-Output "NXT_DetectionSource=Not a Lenovo device"
        exit 0
    }
}
catch {
    $result.Manufacturer = "Unknown"
}

# ── Step 2 : Check WU RebootRequired registry key (primary reboot signal) ─────
# Created exclusively by Windows Update when a WUfB driver needs a restart.
$wuRebootKey     = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
$wuRebootPending = Test-Path $wuRebootKey

if ($wuRebootPending) {
    $result.RestartPending  = "Yes"
    $result.DetectionSource = "WU-RebootRequired-Registry"
}

# ── Step 3 : Secondary registry reboot signals ────────────────────────────────
$rebootSources = @()

# CBS — driver INF processing pending reboot
$cbs = Get-ItemProperty `
       "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing" `
       -ErrorAction SilentlyContinue
if ($cbs.RebootPending) {
    $rebootSources += "CBS-RebootPending"
}

# Session Manager — driver file replacement queued until next boot
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
# Broadened filter to catch generically titled WU driver updates.
if ($result.RestartPending -eq "Yes") {
    try {
        $updateSession  = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $historyCount   = $updateSearcher.GetTotalHistoryCount()

        if ($historyCount -gt 0) {
            $history = $updateSearcher.QueryHistory(0, [Math]::Min($historyCount, 200))
            $cutoff  = (Get-Date).AddDays(-30)

            $lenovoDriverUpdate = $history | Where-Object {
                $_.ResultCode -eq 2 -and
                $_.Date       -ge $cutoff -and
                (
                    $_.Title       -match "(?i)lenovo"   -or
                    $_.Description -match "(?i)lenovo"   -or
                    (
                        $_.Title -match "(?i)driver|(?i)audio|(?i)sound|(?i)network|(?i)bluetooth|(?i)firmware|(?i)chipset|(?i)video|(?i)display|(?i)storage|(?i)thunderbolt|(?i)fingerprint|(?i)camera" -and
                        $_.Title -notmatch "(?i)microsoft|(?i)windows defender|(?i)office"
                    )
                )
            } | Sort-Object Date -Descending | Select-Object -First 1

            if ($lenovoDriverUpdate) {
                $result.DriverName      = $lenovoDriverUpdate.Title
                $result.DetectionSource += " | WU-Update-History"

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
if ($result.RestartPending -eq "Yes") {
    try {
        $cutoff = (Get-Date).AddDays(-30)

        $driverEvents = Get-WinEvent `
                        -LogName "Microsoft-Windows-WindowsUpdateClient/Operational" `
                        -ErrorAction SilentlyContinue |
                        Where-Object {
                            $_.Id          -in @(19, 43) -and
                            $_.TimeCreated -ge $cutoff   -and
                            $_.Message     -match "(?i)lenovo|(?i)driver|(?i)audio|(?i)sound"
                        } |
                        Sort-Object TimeCreated -Descending |
                        Select-Object -First 1

        if ($driverEvents) {
            $result.DetectionSource += " | WU-EventLog(ID:$($driverEvents.Id))"

            if ($result.DriverName -eq "N/A") {
                $titleMatch = [regex]::Match($driverEvents.Message, '(?i)update\s+title[:\s]+(.+)')
                if ($titleMatch.Success) {
                    $result.DriverName = $titleMatch.Groups[1].Value.Trim()
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

# ── Step 6 : Driver Store — get INF details + built date + version ─────────────
# Get-WindowsDriver gives us the INF filename and Lenovo-authored date.
# We use the INF base name to drive both the PnPEntity lookup and the
# DriverStore folder search in Steps 7 and 8.
$infBaseName = $null

if ($result.RestartPending -eq "Yes") {
    try {
        $lenovoDriver = Get-WindowsDriver -Online -ErrorAction SilentlyContinue |
                        Where-Object { $_.ProviderName -like "*Lenovo*" } |
                        Sort-Object Date -Descending |
                        Select-Object -First 1

        if ($lenovoDriver) {
            $infBaseName = [System.IO.Path]::GetFileNameWithoutExtension(
                               $lenovoDriver.OriginalFileName)

            # DriverBuiltDate = when Lenovo signed/authored this driver
            $result.DriverBuiltDate = if ($lenovoDriver.Date) {
                $lenovoDriver.Date.ToString("yyyy-MM-dd")
            } else { "N/A" }

            # Version from Driver Store if not yet resolved
            if ($result.DriverVersion -eq "N/A" -and $lenovoDriver.Version) {
                $result.DriverVersion = $lenovoDriver.Version
            }

            $result.DetectionSource += " | DriverStore-Enriched"
        }
    }
    catch {
        $result.DetectionSource += " | DriverStore-ReadError"
    }
}

# ── Step 7 : Win32_PnPEntity — resolve friendly driver name ───────────────────
# FIX: Win32_PnPEntity is broader than Win32_PnPSignedDriver and always carries
# the human-readable device name (e.g. "Lenovo Audio" instead of lnvvsndmft.inf).
# Match by service name derived from the INF base name.
if ($result.RestartPending -eq "Yes" -and $infBaseName) {
    try {
        # Try matching by service name first (most precise)
        $pnpEntity = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue |
                     Where-Object {
                         $_.Service -like "*$infBaseName*" -or
                         $_.Name    -match "(?i)lenovo" -and
                         $_.Name    -match "(?i)audio|(?i)sound|(?i)network|(?i)bluetooth|(?i)video|(?i)camera|(?i)fingerprint|(?i)storage|(?i)chipset|(?i)thunderbolt|(?i)firmware"
                     } |
                     Select-Object -First 1

        if ($pnpEntity -and $pnpEntity.Name -ne "") {
            $result.DriverName = $pnpEntity.Name
        }
        else {
            # Fallback: any Lenovo-named PnP device
            $pnpFallback = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue |
                           Where-Object { $_.Name -match "(?i)lenovo" } |
                           Select-Object -First 1

            $result.DriverName = if ($pnpFallback -and $pnpFallback.Name -ne "") {
                $pnpFallback.Name
            } else {
                "$infBaseName.inf"   # Last resort — at least keep .inf suffix clear
            }
        }
    }
    catch {
        $result.DetectionSource += " | PnPEntity-ReadError"
    }
}

# ── Step 8 : DriverStore folder creation date — actual install date ────────────
# FIX: The DriverStore FileRepository folder for this driver is created at the
# exact moment Windows Update stages and installs the driver on the device.
# This is the most accurate "installed on this device" timestamp available —
# more reliable than Win32_PnPSignedDriver.InstallDate which is often null.
if ($result.RestartPending -eq "Yes" -and $infBaseName) {
    try {
        $driverStoreRoot = "C:\Windows\System32\DriverStore\FileRepository"

        $driverFolder = Get-ChildItem -Path $driverStoreRoot -Directory `
                        -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -like "$infBaseName*" } |
                        Sort-Object CreationTime -Descending |
                        Select-Object -First 1

        if ($driverFolder) {
            # CreationTime = when WU staged this driver on the device
            $result.DriverInstallDate = $driverFolder.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
            $result.DetectionSource  += " | DriverStore-FolderDate"
        }
    }
    catch {
        $result.DetectionSource += " | DriverStore-FolderDate-Error"
    }
}

# ── Step 9 : Output formatted report ──────────────────────────────────────────
Write-Output ""
Write-Output "========================================"
Write-Output " Lenovo Driver Reboot Detection Report"
Write-Output "========================================"
Write-Output "Device Name         : $($result.DeviceName)"
Write-Output "Manufacturer        : $($result.Manufacturer)"
Write-Output "Restart Pending     : $($result.RestartPending)"

if ($result.RestartPending -eq "Yes") {
    Write-Output "Driver Name         : $($result.DriverName)"
    Write-Output "Driver Version      : $($result.DriverVersion)"
    Write-Output "Driver Built Date   : $($result.DriverBuiltDate)  (date Lenovo signed the driver)"
    Write-Output "Driver Install Date : $($result.DriverInstallDate)  (date WU installed it on this device)"
    Write-Output "Detection Source    : $($result.DetectionSource)"
}
else {
    Write-Output "Result              : No Lenovo driver restart pending detected"
}

Write-Output "========================================"
Write-Output ""

# ── Step 10 : Nexthink Remote Action output variables ─────────────────────────
# Register these as output variables in the Nexthink Remote Action definition
Write-Output "NXT_RestartPending=$($result.RestartPending)"
Write-Output "NXT_DriverName=$($result.DriverName)"
Write-Output "NXT_DriverVersion=$($result.DriverVersion)"
Write-Output "NXT_DriverBuiltDate=$($result.DriverBuiltDate)"
Write-Output "NXT_DriverInstallDate=$($result.DriverInstallDate)"
Write-Output "NXT_DetectionSource=$($result.DetectionSource)"

# ── Exit codes for Intune Proactive Remediation ────────────────────────────────
# Exit 1 = Restart pending (non-compliant — triggers remediation action)
# Exit 0 = No restart pending (compliant)
if ($result.RestartPending -eq "Yes") { exit 1 } else { exit 0 }
