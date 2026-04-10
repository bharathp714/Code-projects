#Requires -Version 5.1
# =============================================================================
# Script  : Lenovo-DriverReboot-Detection.ps1
# Purpose : Detect Lenovo driver updates (delivered via Intune WUfB driver
#           policy) that completed successfully but require a restart
# Output  : Restart Pending (Yes/No), Driver Name, Driver Version,
#           Driver Built Date, Driver Install Date, Reboot Flag Date,
#           Days Pending
# Sources : WU registry keys, WU history (COM), WU event log,
#           Windows Driver Store, Win32_PnPSignedDriver.DeviceName,
#           DriverStore folder creation date, INF file [Strings] section,
#           Hardware ID to PnP device name mapping
# Usage   : Run locally, via Nexthink Remote Action, or Intune Proactive
#           Remediation (detection script)
#
# Fixes (PS 5.1): return-if syntax, CBS RebootPending subkey, filtered WU events
# =============================================================================

# ── Initialise result object ──────────────────────────────────────────────────
$result = [PSCustomObject]@{
    DeviceName        = $env:COMPUTERNAME
    Manufacturer      = ""
    RestartPending    = "No"
    DriverName        = "N/A"
    DriverVersion     = "N/A"
    DriverBuiltDate   = "N/A"
    DriverInstallDate = "N/A"
    RebootFlagDate    = "N/A"
    DaysPending       = "N/A"
    DetectionSource   = "N/A"
}

# ── Helper : Test if driver name needs further resolution ─────────────────────
function NameNeedsResolution {
    param($name)
    return (
        $name -eq "N/A"                        -or
        $name -notmatch "(?i)lenovo"           -or
        $name -match "(?i)^lenovo extension"   -or
        $name -match "(?i)^lenovo \w+ driver$"
    )
}

# ── Helper : Parse a named key from INF content ───────────────────────────────
# Handles both INF value formats:
#   Format A — token reference : ServiceDescription = %ServiceDescription%
#   Format B — inline quoted   : ServiceDescription="Lenovo Vision Service"
function Get-InfValue {
    param(
        [string[]] $infContent,
        [string]   $keyPattern
    )
    try {
        $escapedKey = [regex]::Escape($keyPattern)

        $line = $infContent |
                Select-String "^\s*$escapedKey\s*=" |
                Select-Object -First 1

        if (-not $line) { return $null }

        $raw = ($line.Line -split '=', 2)[-1].Trim().Trim('"').Trim("'")

        if ($raw -match '^%(.+)%$') {
            $token     = [regex]::Escape($Matches[1])
            $tokenLine = $infContent |
                         Select-String "^\s*$token\s*=" |
                         Select-Object -First 1
            if ($tokenLine) {
                $raw = ($tokenLine.Line -split '=', 2)[-1].Trim().Trim('"').Trim("'")
            }
        }

        # PowerShell 5.1: do not use "return if (...) { }" — it is not valid syntax.
        if ($raw -ne "" -and $raw -notmatch "^%") { return $raw }
        return $null
    }
    catch { return $null }
}

# ── Helper : Calculate DaysPending from a DateTime ────────────────────────────
function Set-DaysPending {
    param([datetime]$flagDateTime, [ref]$resultObj)
    $resultObj.Value.RebootFlagDate = $flagDateTime.ToString("yyyy-MM-dd HH:mm:ss")
    $resultObj.Value.DaysPending    = [math]::Round(
                                          ((Get-Date) - $flagDateTime).TotalDays, 0
                                      ).ToString()
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
        Write-Output "NXT_RebootFlagDate=N/A"
        Write-Output "NXT_DaysPending=N/A"
        Write-Output "NXT_DetectionSource=Not a Lenovo device"
        exit 0
    }
}
catch { $result.Manufacturer = "Unknown" }

# ── Step 2 : Check WU RebootRequired registry key (primary reboot signal) ─────
$wuRebootKey     = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
$wuRebootPending = Test-Path $wuRebootKey

if ($wuRebootPending) {
    $result.RestartPending  = "Yes"
    $result.DetectionSource = "WU-RebootRequired-Registry"

    try {
        $wuKeyItem = Get-Item $wuRebootKey -ErrorAction SilentlyContinue
        if ($wuKeyItem -and $wuKeyItem.LastWriteTime -and
            $wuKeyItem.LastWriteTime -gt [datetime]"2000-01-01") {
            Set-DaysPending -flagDateTime $wuKeyItem.LastWriteTime -resultObj ([ref]$result)
        }
    }
    catch {}
}

# ── Step 3 : Secondary registry reboot signals ────────────────────────────────
$rebootSources = @()

# CBS: RebootPending is a subkey, not a value on the parent Component Based Servicing key.
$cbsRebootPendingKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
try {
    if (Test-Path -LiteralPath $cbsRebootPendingKey) {
        $rebootSources += "CBS-RebootPending"
    }
}
catch { }

$sm = Get-ItemProperty `
      "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
      -ErrorAction SilentlyContinue
if ($sm.PendingFileRenameOperations) { $rebootSources += "PendingFileRenameOperations" }

$wuReboot2 = Get-ItemProperty `
             "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" `
             -ErrorAction SilentlyContinue
if ($wuReboot2.RebootRequired -eq 1) { $rebootSources += "WU-AutoUpdate-RebootRequired" }

if ($rebootSources.Count -gt 0) {
    $result.RestartPending = "Yes"
    if ($result.DetectionSource -eq "N/A") {
        $result.DetectionSource = $rebootSources -join " | "
    } else {
        $result.DetectionSource += " | " + ($rebootSources -join " | ")
    }
}

# ── Step 4 : Windows Update history — get driver name + version ───────────────
if ($result.RestartPending -eq "Yes") {
    try {
        $updateSession  = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $historyCount   = $updateSearcher.GetTotalHistoryCount()

        if ($historyCount -gt 0) {
            $history = $updateSearcher.QueryHistory(0, [Math]::Min($historyCount, 200))
            $cutoff  = (Get-Date).AddDays(-30)

            # Primary — Lenovo-explicit titles only
            $lenovoDriverUpdate = $history | Where-Object {
                $_.ResultCode -eq 2 -and $_.Date -ge $cutoff -and
                ($_.Title -match "(?i)lenovo" -or $_.Description -match "(?i)lenovo")
            } | Sort-Object Date -Descending | Select-Object -First 1

            # Secondary — driver keywords, excluding known non-Lenovo vendors
            if (-not $lenovoDriverUpdate) {
                $lenovoDriverUpdate = $history | Where-Object {
                    $_.ResultCode -eq 2 -and $_.Date -ge $cutoff -and
                    $_.Title -match "(?i)driver|(?i)audio|(?i)sound|(?i)network|(?i)bluetooth|(?i)firmware|(?i)chipset|(?i)video|(?i)display|(?i)storage|(?i)thunderbolt|(?i)fingerprint|(?i)camera" -and
                    $_.Title -notmatch "(?i)microsoft|(?i)windows defender|(?i)office|(?i)intel|(?i)realtek|(?i)broadcom|(?i)qualcomm|(?i)nvidia|(?i)amd"
                } | Sort-Object Date -Descending | Select-Object -First 1
            }

            if ($lenovoDriverUpdate) {
                $result.DriverName      = $lenovoDriverUpdate.Title
                $result.DetectionSource += " | WU-Update-History"

                $versionMatch = [regex]::Match($lenovoDriverUpdate.Title, '\d+\.\d+\.\d+\.\d+')
                if ($versionMatch.Success) { $result.DriverVersion = $versionMatch.Value }
            }
        }
    }
    catch { $result.DetectionSource += " | WU-History-Error: $($_.Exception.Message)" }
}

# ── Step 5 : Windows Update event log — Event ID 19 / 43 ─────────────────────
if ($result.RestartPending -eq "Yes") {
    try {
        $cutoff = (Get-Date).AddDays(-30)

        $driverEvents = $null
        try {
            $driverEvents = Get-WinEvent -FilterHashtable @{
                LogName   = 'Microsoft-Windows-WindowsUpdateClient/Operational'
                Id        = 19, 43
                StartTime = $cutoff
            } -MaxEvents 500 -ErrorAction SilentlyContinue |
                Where-Object { $_.Message -match '(?i)lenovo|driver|audio|sound' } |
                Sort-Object TimeCreated -Descending |
                Select-Object -First 1
        }
        catch { $driverEvents = $null }

        if ($driverEvents) {
            $result.DetectionSource += " | WU-EventLog(ID:$($driverEvents.Id))"
            if ($result.DriverName -eq "N/A") {
                $titleMatch = [regex]::Match($driverEvents.Message, '(?i)update\s+title[:\s]+(.+)')
                if (-not $titleMatch.Success) {
                    $titleMatch = [regex]::Match($driverEvents.Message, '(?i)following update:\s*(.+)')
                }
                if ($titleMatch.Success) { $result.DriverName = $titleMatch.Groups[1].Value.Trim() }
            }
        }

        $systemRebootEvent = $null
        try {
            $systemRebootEvent = Get-WinEvent -FilterHashtable @{
                LogName   = 'System'
                Id        = 20
                StartTime = $cutoff
            } -MaxEvents 200 -ErrorAction SilentlyContinue |
                Where-Object { $_.ProviderName -match '(?i)WindowsUpdateClient' } |
                Sort-Object TimeCreated -Descending |
                Select-Object -First 1
        }
        catch { $systemRebootEvent = $null }

        if ($systemRebootEvent) { $result.DetectionSource += " | System-EventLog(ID:20)" }
    }
    catch { $result.DetectionSource += " | EventLog-ReadError" }
}

# ── Step 6 : Driver Store — INF base name + built date + version ──────────────
$infBaseName       = $null
$driverStoreFolder = $null
$infContent        = $null

if ($result.RestartPending -eq "Yes") {
    try {
        $lenovoDriver = Get-WindowsDriver -Online -ErrorAction SilentlyContinue |
                        Where-Object { $_.ProviderName -like "*Lenovo*" } |
                        Sort-Object Date -Descending | Select-Object -First 1

        if ($lenovoDriver) {
            $infBaseName = [System.IO.Path]::GetFileNameWithoutExtension(
                               $lenovoDriver.OriginalFileName)

            $result.DriverBuiltDate = if ($lenovoDriver.Date) {
                $lenovoDriver.Date.ToString("yyyy-MM-dd")
            } else { "N/A" }

            if ($result.DriverVersion -eq "N/A" -and $lenovoDriver.Version) {
                $result.DriverVersion = $lenovoDriver.Version
            }

            $driverStoreRoot   = "C:\Windows\System32\DriverStore\FileRepository"
            $driverStoreFolder = Get-ChildItem -Path $driverStoreRoot -Directory `
                                 -ErrorAction SilentlyContinue |
                                 Where-Object { $_.Name -like "$infBaseName*" } |
                                 Sort-Object CreationTime -Descending | Select-Object -First 1

            if ($driverStoreFolder) {
                $infFile = Get-ChildItem -Path $driverStoreFolder.FullName `
                           -ErrorAction SilentlyContinue |
                           Where-Object { $_.Name -like "$infBaseName.inf" } |
                           Select-Object -First 1

                if ($infFile) {
                    $infContent = Get-Content $infFile.FullName -ErrorAction SilentlyContinue
                }
            }

            $result.DetectionSource += " | DriverStore-Enriched"

            if ($result.DriverName -ne "N/A" -and
                $result.DriverName -notmatch "(?i)lenovo" -and
                $infBaseName -match "^lnv") {
                $result.DriverName       = "N/A"
                $result.DetectionSource += " | WU-History-Overridden(non-Lenovo-title)"
            }
        }
    }
    catch { $result.DetectionSource += " | DriverStore-ReadError: $($_.Exception.Message)" }
}

# ── Step 7 : Win32_PnPSignedDriver.DeviceName ────────────────────────────────
if ($result.RestartPending -eq "Yes" -and $infBaseName -and (NameNeedsResolution $result.DriverName)) {
    try {
        $pnpSigned = Get-WmiObject Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
                     Where-Object { $_.InfName -like "$infBaseName*" } | Select-Object -First 1

        if ($pnpSigned -and $pnpSigned.DeviceName -and
            $pnpSigned.DeviceName -ne "" -and
            $pnpSigned.DeviceName -match "(?i)lenovo") {
            $result.DriverName = $pnpSigned.DeviceName
        } elseif ($pnpSigned -and $pnpSigned.Description -and
                  $pnpSigned.Description -ne "" -and
                  $pnpSigned.Description -match "(?i)lenovo") {
            $result.DriverName = $pnpSigned.Description
        }
    }
    catch { $result.DetectionSource += " | PnPSignedDriver-ReadError" }
}

# ── Step 8 : DriverStore folder creation date — actual WU install date ─────────
if ($result.RestartPending -eq "Yes" -and $driverStoreFolder) {
    try {
        $folderCreationTime       = $driverStoreFolder.CreationTime
        $result.DriverInstallDate = $folderCreationTime.ToString("yyyy-MM-dd HH:mm:ss")
        $result.DetectionSource  += " | DriverStore-FolderDate"

        if ($result.RebootFlagDate -eq "N/A") {
            Set-DaysPending -flagDateTime $folderCreationTime -resultObj ([ref]$result)
            $result.DetectionSource += " | RebootFlagDate-DriverStoreFolder"
        }
    }
    catch { $result.DetectionSource += " | DriverStore-FolderDate-Error" }
}

# ── Step 9 : INF file [Strings] parsing ───────────────────────────────────────
if ($result.RestartPending -eq "Yes" -and $infContent -and (NameNeedsResolution $result.DriverName)) {

    $parseInfKey = {
        param([string]$key)
        $escapedKey = [regex]::Escape($key)
        $matched = $infContent | Select-String "^\s*$escapedKey\s*=" | Select-Object -First 1
        if (-not $matched) { return $null }
        $val = ($matched.Line -split '=', 2)[-1].Trim().Trim('"').Trim("'")
        if ($val -match '^%(.+)%$') {
            $tok = [regex]::Escape($Matches[1])
            $tokLine = $infContent | Select-String "^\s*$tok\s*=" | Select-Object -First 1
            if ($tokLine) { $val = ($tokLine.Line -split '=', 2)[-1].Trim().Trim('"').Trim("'") }
        }
        if ($val -ne "" -and $val -notmatch "^%") { return $val }
        return $null
    }

    $parsed = & $parseInfKey "ServiceDescription"
    if ($parsed) {
        $result.DriverName      = $parsed
        $result.DetectionSource += " | INF-ServiceDescription"
    }

    if (NameNeedsResolution $result.DriverName) {
        $parsed = & $parseInfKey "InstallServiceDescription"
        if ($parsed) {
            $result.DriverName      = $parsed
            $result.DetectionSource += " | INF-InstallServiceDescription"
        }
    }

    if (NameNeedsResolution $result.DriverName) {
        $parsed = & $parseInfKey "DriverDesc"
        if ($parsed) {
            $result.DriverName      = $parsed
            $result.DetectionSource += " | INF-DriverDesc"
        }
    }

    if (NameNeedsResolution $result.DriverName) {
        $parsed = & $parseInfKey "ProductName"
        if ($parsed) {
            $result.DriverName      = $parsed
            $result.DetectionSource += " | INF-ProductName"
        }
    }

    if (NameNeedsResolution $result.DriverName) {
        $parsed = & $parseInfKey "Description"
        if ($parsed -and $parsed -notmatch "^%") {
            $result.DriverName      = $parsed
            $result.DetectionSource += " | INF-Description"
        }
    }

    if (NameNeedsResolution $result.DriverName) {
        $parsed = & $parseInfKey "Class"
        if ($parsed -and $parsed -notmatch "^\{" -and $parsed -notmatch "(?i)^extension$") {
            $result.DriverName      = "Lenovo $parsed Driver"
            $result.DetectionSource += " | INF-Class"
        }
    }
}

# ── Step 10 : Hardware ID → PnP device name mapping ───────────────────────────
if ($result.RestartPending -eq "Yes" -and $infContent -and (NameNeedsResolution $result.DriverName)) {
    try {
        $hwIdLines = $infContent |
                     Select-String '(?i)(HDAUDIO|PCI|USB|ACPI|HID|ROOT|SWC|SWD)\\[^\s,;]+' |
                     Select-Object -First 5

        if ($hwIdLines) {
            $allPnpEntities = Get-WmiObject Win32_PnPEntity -ErrorAction SilentlyContinue

            foreach ($hwIdLine in $hwIdLines) {
                $hwIdMatch = [regex]::Match(
                    $hwIdLine.Line,
                    '(?i)(HDAUDIO|PCI|USB|ACPI|HID|ROOT|SWC|SWD)\\[^\s,;"]+')

                if ($hwIdMatch.Success) {
                    $hwId          = $hwIdMatch.Value.Trim()
                    $matchedDevice = $allPnpEntities | Where-Object {
                        $_.HardwareID -contains $hwId -and
                        $_.Name -ne $null -and $_.Name -ne ""
                    } | Select-Object -First 1

                    if ($matchedDevice) {
                        $baseName          = $matchedDevice.Name
                        $result.DriverName = if ($baseName -match "(?i)lenovo") {
                            $baseName
                        } else {
                            "Lenovo Driver Extension - $baseName"
                        }
                        $result.DetectionSource += " | HardwareID-PnPMatch"
                        break
                    }
                }
            }
        }
    }
    catch { $result.DetectionSource += " | HardwareID-LookupError" }

    if (NameNeedsResolution $result.DriverName) {
        $result.DriverName = $infBaseName
    }
}

# ── Step 11 : Output formatted report ─────────────────────────────────────────
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
    Write-Output "Driver Install Date : $($result.DriverInstallDate)  (date WU staged it on this device)"
    Write-Output "Reboot Flag Date    : $($result.RebootFlagDate)  (date reboot pending flag was set)"
    Write-Output "Days Pending        : $($result.DaysPending) day(s)"
    Write-Output "Detection Source    : $($result.DetectionSource)"
} else {
    Write-Output "Result              : No Lenovo driver restart pending detected"
}

Write-Output "========================================"
Write-Output ""

# ── Step 12 : Nexthink Remote Action output variables ─────────────────────────
Write-Output "NXT_RestartPending=$($result.RestartPending)"
Write-Output "NXT_DriverName=$($result.DriverName)"
Write-Output "NXT_DriverVersion=$($result.DriverVersion)"
Write-Output "NXT_DriverBuiltDate=$($result.DriverBuiltDate)"
Write-Output "NXT_DriverInstallDate=$($result.DriverInstallDate)"
Write-Output "NXT_RebootFlagDate=$($result.RebootFlagDate)"
Write-Output "NXT_DaysPending=$($result.DaysPending)"
Write-Output "NXT_DetectionSource=$($result.DetectionSource)"

# ── Exit codes for Intune Proactive Remediation ────────────────────────────────
if ($result.RestartPending -eq "Yes") { exit 1 } else { exit 0 }
