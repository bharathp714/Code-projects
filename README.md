# =============================================================================
# Script  : Lenovo-DriverReboot-Detection.ps1
# Purpose : Detect Lenovo driver updates (delivered via Intune WUfB driver
#           policy) that completed successfully but require a restart
# Output  : Restart Pending (Yes/No), Driver Name, Driver Version,
#           Driver Built Date, Actual Install Date on Device
# Sources : WU registry keys, WU history (COM), WU event log,
#           Windows Driver Store, Win32_PnPSignedDriver.DeviceName,
#           DriverStore folder creation date, INF file [Strings] section
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
# Searches WU install history for Lenovo-related driver updates in last 30 days.
# FIX: After matching, we cross-validate the title against the actual INF vendor.
# If the WU title belongs to a different vendor (Intel, Realtek etc.), it is
# discarded so the INF parsing in Step 9 can provide the correct name instead.
if ($result.RestartPending -eq "Yes") {
    try {
        $updateSession  = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $historyCount   = $updateSearcher.GetTotalHistoryCount()

        if ($historyCount -gt 0) {
            $history = $updateSearcher.QueryHistory(0, [Math]::Min($historyCount, 200))
            $cutoff  = (Get-Date).AddDays(-30)

            # Primary: Lenovo-explicit titles only (most trustworthy)
            $lenovoDriverUpdate = $history | Where-Object {
                $_.ResultCode -eq 2 -and
                $_.Date       -ge $cutoff -and
                (
                    $_.Title       -match "(?i)lenovo" -or
                    $_.Description -match "(?i)lenovo"
                )
            } | Sort-Object Date -Descending | Select-Object -First 1

            # Secondary: broader driver keyword match only if no Lenovo-explicit hit
            if (-not $lenovoDriverUpdate) {
                $lenovoDriverUpdate = $history | Where-Object {
                    $_.ResultCode -eq 2 -and
                    $_.Date       -ge $cutoff -and
                    $_.Title -match "(?i)driver|(?i)audio|(?i)sound|(?i)network|(?i)bluetooth|(?i)firmware|(?i)chipset|(?i)video|(?i)display|(?i)storage|(?i)thunderbolt|(?i)fingerprint|(?i)camera" -and
                    $_.Title -notmatch "(?i)microsoft|(?i)windows defender|(?i)office|(?i)intel|(?i)realtek|(?i)broadcom|(?i)qualcomm|(?i)nvidia|(?i)amd"
                } | Sort-Object Date -Descending | Select-Object -First 1
            }

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

# ── Step 6 : Driver Store — get INF base name + built date + version ──────────
# Get-WindowsDriver returns INF filename and Lenovo-authored date.
# $infBaseName and $driverStoreFolder are used in Steps 7, 8 and 9.
$infBaseName       = $null
$driverStoreFolder = $null

if ($result.RestartPending -eq "Yes") {
    try {
        $lenovoDriver = Get-WindowsDriver -Online -ErrorAction SilentlyContinue |
                        Where-Object { $_.ProviderName -like "*Lenovo*" } |
                        Sort-Object Date -Descending |
                        Select-Object -First 1

        if ($lenovoDriver) {
            $infBaseName = [System.IO.Path]::GetFileNameWithoutExtension(
                               $lenovoDriver.OriginalFileName)

            # DriverBuiltDate = when Lenovo signed/authored this driver package
            $result.DriverBuiltDate = if ($lenovoDriver.Date) {
                $lenovoDriver.Date.ToString("yyyy-MM-dd")
            } else { "N/A" }

            # Version from Driver Store if not yet resolved
            if ($result.DriverVersion -eq "N/A" -and $lenovoDriver.Version) {
                $result.DriverVersion = $lenovoDriver.Version
            }

            # Locate DriverStore folder — used in Steps 8 and 9
            $driverStoreRoot   = "C:\Windows\System32\DriverStore\FileRepository"
            $driverStoreFolder = Get-ChildItem -Path $driverStoreRoot -Directory `
                                 -ErrorAction SilentlyContinue |
                                 Where-Object { $_.Name -like "$infBaseName*" } |
                                 Sort-Object CreationTime -Descending |
                                 Select-Object -First 1

            $result.DetectionSource += " | DriverStore-Enriched"

            # FIX: Cross-validate WU history name against the actual Lenovo INF.
            # If the resolved driver name doesn't mention Lenovo AND the INF name
            # is a known Lenovo prefix (lnv*), the WU history matched the wrong
            # driver (e.g. Intel). Reset so INF parsing takes over in Step 9.
            if ($result.DriverName -ne "N/A" -and
                $result.DriverName -notmatch "(?i)lenovo" -and
                $infBaseName -match "^lnv") {
                $result.DriverName       = "N/A"
                $result.DetectionSource += " | WU-History-Overridden(non-Lenovo-title)"
            }
        }
    }
    catch {
        $result.DetectionSource += " | DriverStore-ReadError"
    }
}

# ── Step 7 : Win32_PnPSignedDriver.DeviceName — precise friendly name ─────────
# Works for standard PnP drivers. Kernel filter drivers return empty here
# and fall through to Step 9 INF parsing.
if ($result.RestartPending -eq "Yes" -and $infBaseName -and $result.DriverName -eq "N/A") {
    try {
        $pnpSigned = Get-WmiObject Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
                     Where-Object { $_.InfName -like "$infBaseName*" } |
                     Select-Object -First 1

        if ($pnpSigned -and $pnpSigned.DeviceName -and $pnpSigned.DeviceName -ne "") {
            $result.DriverName = $pnpSigned.DeviceName
        }
        elseif ($pnpSigned -and $pnpSigned.Description -and $pnpSigned.Description -ne "") {
            $result.DriverName = $pnpSigned.Description
        }
        # Empty = kernel filter driver — falls through to Step 9
    }
    catch {
        $result.DetectionSource += " | PnPSignedDriver-ReadError"
    }
}

# ── Step 8 : DriverStore folder creation date — actual WU install date ─────────
# The FileRepository folder is created at the exact moment WU stages the driver.
if ($result.RestartPending -eq "Yes" -and $driverStoreFolder) {
    try {
        $result.DriverInstallDate = $driverStoreFolder.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
        $result.DetectionSource  += " | DriverStore-FolderDate"
    }
    catch {
        $result.DetectionSource += " | DriverStore-FolderDate-Error"
    }
}

# ── Step 9 : INF file [Strings] parsing — driver name from INF itself ──────────
# Triggered when:
#   - DriverName is still N/A (PnP lookup failed — kernel filter driver), OR
#   - DriverName doesn't contain "Lenovo" (WU history returned wrong vendor)
# Reads the INF directly from the DriverStore folder.
# Priority order: DriverDesc → ProductName → Description → Class
$needsInfParsing = (
    $result.RestartPending -eq "Yes" -and
    $driverStoreFolder -and
    $infBaseName -and
    ($result.DriverName -eq "N/A" -or $result.DriverName -notmatch "(?i)lenovo")
)

if ($needsInfParsing) {
    try {
        $infFile = Get-ChildItem -Path $driverStoreFolder.FullName `
                   -Filter "$infBaseName.inf" -ErrorAction SilentlyContinue |
                   Select-Object -First 1

        if ($infFile) {
            $infContent = Get-Content $infFile.FullName -ErrorAction SilentlyContinue

            # Priority 1 — DriverDesc in [Strings] section (most descriptive)
            $driverDescLine = $infContent | Select-String '^\s*DriverDesc\s*=' |
                              Select-Object -First 1
            if ($driverDescLine) {
                $parsed = ($driverDescLine -split '=', 2)[-1].Trim().Trim('"')
                if ($parsed -ne "") {
                    $result.DriverName      = $parsed
                    $result.DetectionSource += " | INF-DriverDesc"
                }
            }

            # Priority 2 — ProductName in [Strings] section
            if ($result.DriverName -eq "N/A" -or $result.DriverName -notmatch "(?i)lenovo") {
                $productLine = $infContent | Select-String '^\s*ProductName\s*=' |
                               Select-Object -First 1
                if ($productLine) {
                    $parsed = ($productLine -split '=', 2)[-1].Trim().Trim('"')
                    if ($parsed -ne "") {
                        $result.DriverName      = $parsed
                        $result.DetectionSource += " | INF-ProductName"
                    }
                }
            }

            # Priority 3 — Description under [Version] section
            if ($result.DriverName -eq "N/A" -or $result.DriverName -notmatch "(?i)lenovo") {
                $versionDesc = $infContent | Select-String '^\s*Description\s*=' |
                               Select-Object -First 1
                if ($versionDesc) {
                    $parsed = ($versionDesc -split '=', 2)[-1].Trim().Trim('"')
                    if ($parsed -ne "") {
                        $result.DriverName      = $parsed
                        $result.DetectionSource += " | INF-Description"
                    }
                }
            }

            # Priority 4 — Class name from [Version] as last meaningful fallback
            if ($result.DriverName -eq "N/A" -or $result.DriverName -notmatch "(?i)lenovo") {
                $classLine = $infContent | Select-String '^\s*ClassDesc\s*=|^\s*Class\s*=' |
                             Select-Object -First 1
                if ($classLine) {
                    $parsed = ($classLine -split '=', 2)[-1].Trim().Trim('"')
                    if ($parsed -ne "" -and $parsed -notmatch "^\{") {
                        $result.DriverName      = "Lenovo $parsed Driver"
                        $result.DetectionSource += " | INF-Class"
                    }
                }
            }
        }
    }
    catch {
        $result.DetectionSource += " | INF-ParseError"
    }

    # Absolute last resort — clean INF basename without (INF) suffix
    if ($result.DriverName -eq "N/A") {
        $result.DriverName = $infBaseName
    }
}

# ── Step 10 : Output formatted report ─────────────────────────────────────────
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

# ── Step 11 : Nexthink Remote Action output variables ─────────────────────────
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
