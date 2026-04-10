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
# FIX: Now handles both INF value formats:
#   Format A — token reference : ServiceDescription = %ServiceDescription%
#   Format B — inline quoted   : ServiceDescription="Lenovo Vision Service"
# Both are common in Lenovo INF files. Previously only Format A was handled.
function Get-InfValue {
    param(
        [string[]] $infContent,
        [string]   $keyPattern
    )
    try {
        $escapedKey = [regex]::Escape($keyPattern)

        # Match key regardless of spacing or quoting style around =
        $line = $infContent |
                Select-String "^\s*$escapedKey\s*=\s*" |
                Select-Object -First 1

        if (-not $line) { return $null }

        # Extract everything after the first = and strip surrounding quotes
        $raw = ($line.Line -split '=', 2)[-1].Trim().Trim('"')

        # If value is a %Token% reference, resolve it from the [Strings] section
        if ($raw -match '^%(.+)%$') {
            $token     = [regex]::Escape($Matches[1])
            $tokenLine = $infContent |
                         Select-String "^\s*$token\s*=\s*" |
                         Select-Object -First 1
            if ($tokenLine) {
                $raw = ($tokenLine.Line -split '=', 2)[-1].Trim().Trim('"')
            }
        }

        return if ($raw -ne "" -and $raw -notmatch "^%") { $raw } else { $null }
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

$cbs = Get-ItemProperty `
       "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing" `
       -ErrorAction SilentlyContinue
if ($cbs.RebootPending) { $rebootSources += "CBS-RebootPending" }

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

        $driverEvents = Get-WinEvent `
                        -LogName "Microsoft-Windows-WindowsUpdateClient/Operational" `
                        -ErrorAction SilentlyContinue |
                        Where-Object {
                            $_.Id -in @(19, 43) -and $_.TimeCreated -ge $cutoff -and
                            $_.Message -match "(?i)lenovo|(?i)driver|(?i)audio|(?i)sound"
                        } | Sort-Object TimeCreated -Descending | Select-Object -First 1

        if ($driverEvents) {
            $result.DetectionSource += " | WU-EventLog(ID:$($driverEvents.Id))"
            if ($result.DriverName -eq "N/A") {
                $titleMatch = [regex]::Match($driverEvents.Message, '(?i)update\s+title[:\s]+(.+)')
                if ($titleMatch.Success) { $result.DriverName = $titleMatch.Groups[1].Value.Trim() }
            }
        }

        $systemRebootEvent = Get-WinEvent -LogName "System" -ErrorAction SilentlyContinue |
                             Where-Object {
                                 $_.Id -eq 20 -and $_.TimeCreated -ge $cutoff -and
                                 $_.ProviderName -match "(?i)WindowsUpdateClient"
                             } | Sort-Object TimeCreated -Descending | Select-Object -First 1

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

            # Case-insensitive INF file lookup — confirmed filename on disk is
            # mixed case "LnvVsnDmft.inf" vs lowercase infBaseName "lnvvsndmft"
            if ($driverStoreFolder) {
                $infFile = Get-ChildItem -Path $driverStoreFolder.FullName `
                           -ErrorAction SilentlyContinue |
                           Where-Object { $_.Name -like "$infBaseName.inf" } |
                           Select-Object -First 1

                if ($infFile) {
                    # Get-Content without -Raw returns string[] directly —
                    # exactly what Select-String and Get-InfValue expect.
                    # Using -Raw caused Select-String to behave differently
                    # on a single string vs an array, breaking INF parsing.
                    $infContent = Get-Content $infFile.FullName -ErrorAction SilentlyContinue
                }
            }

            $result.DetectionSource += " | DriverStore-Enriched"

            # Cross-validate WU history — discard if non-Lenovo vendor matched
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

        if ($pnpSigned -and $pnpSigned.DeviceName -and $pnpSigned.DeviceName -ne "") {
            $result.DriverName = $pnpSigned.DeviceName
        } elseif ($pnpSigned -and $pnpSigned.Description -and $pnpSigned.Description -ne "") {
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

        # FIX: Directly set RebootFlagDate from DriverStore folder CreationTime here
        # since Session Manager LastWriteTime is unreliable (returns blank).
        # DriverStore CreationTime = when WU staged the driver = same event that
        # triggered PendingFileRenameOperations. No conditional check needed —
        # if WU key already set it in Step 2, this will simply overwrite with the
        # same or more accurate value.
        if ($result.RebootFlagDate -eq "N/A") {
            Set-DaysPending -flagDateTime $folderCreationTime -resultObj ([ref]$result)
            $result.DetectionSource += " | RebootFlagDate-DriverStoreFolder"
        }
    }
    catch { $result.DetectionSource += " | DriverStore-FolderDate-Error" }
}

# ── Step 9 : INF file [Strings] parsing ───────────────────────────────────────
# FIX: Get-InfValue now handles both INF value formats:
#   ServiceDescription = %Token%              ← token reference (resolved)
#   ServiceDescription="Lenovo Vision Service" ← inline quoted (parsed directly)
# Confirmed present in LnvVsnDmft.inf:
#   ServiceDescription="Lenovo Vision Service"
#   InstallServiceDescription="Lenovo View Install Service"
if ($result.RestartPending -eq "Yes" -and $infContent -and (NameNeedsResolution $result.DriverName)) {

    # Priority 1 — ServiceDescription → "Lenovo Vision Service"
    $parsed = Get-InfValue -infContent $infContent -keyPattern "ServiceDescription"
    if ($parsed) {
        $result.DriverName      = $parsed
        $result.DetectionSource += " | INF-ServiceDescription"
    }

    # Priority 2 — InstallServiceDescription → "Lenovo View Install Service"
    if (NameNeedsResolution $result.DriverName) {
        $parsed = Get-InfValue -infContent $infContent -keyPattern "InstallServiceDescription"
        if ($parsed) {
            $result.DriverName      = $parsed
            $result.DetectionSource += " | INF-InstallServiceDescription"
        }
    }

    # Priority 3 — DriverDesc
    if (NameNeedsResolution $result.DriverName) {
        $parsed = Get-InfValue -infContent $infContent -keyPattern "DriverDesc"
        if ($parsed) {
            $result.DriverName      = $parsed
            $result.DetectionSource += " | INF-DriverDesc"
        }
    }

    # Priority 4 — ProductName
    if (NameNeedsResolution $result.DriverName) {
        $parsed = Get-InfValue -infContent $infContent -keyPattern "ProductName"
        if ($parsed) {
            $result.DriverName      = $parsed
            $result.DetectionSource += " | INF-ProductName"
        }
    }

    # Priority 5 — Description
    if (NameNeedsResolution $result.DriverName) {
        $parsed = Get-InfValue -infContent $infContent -keyPattern "Description"
        if ($parsed -and $parsed -notmatch "^%") {
            $result.DriverName      = $parsed
            $result.DetectionSource += " | INF-Description"
        }
    }

    # Priority 6 — Class (skip "Extension" — too generic)
    if (NameNeedsResolution $result.DriverName) {
        $parsed = Get-InfValue -infContent $infContent -keyPattern "Class"
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

    # Absolute last resort — clean INF basename
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
# Exit 1 = Restart pending (non-compliant — triggers remediation action)

# Exit 0 = No restart pending (compliant)
if ($result.RestartPending -eq "Yes") { exit 1 } else { exit 0 }

$infBaseName = "lnvvsndmft"

$driverStoreRoot = "C:\Windows\System32\DriverStore\FileRepository"
$folder = Get-ChildItem $driverStoreRoot -Directory | 
          Where-Object { $_.Name -like "$infBaseName*" } | 
          Sort-Object CreationTime -Descending | Select-Object -First 1
Write-Output "Folder found: $($folder.FullName)"

$infFile = Get-ChildItem $folder.FullName | 
           Where-Object { $_.Name -like "$infBaseName.inf" } | 
           Select-Object -First 1
Write-Output "INF found: $($infFile.FullName)"

$infContent = Get-Content $infFile.FullName -ErrorAction SilentlyContinue
Write-Output "Content type: $($infContent.GetType().Name)"
Write-Output "Content count: $($infContent.Count)"

$match = $infContent | Select-String "^\s*ServiceDescription\s*="
Write-Output "ServiceDescription match: $($match)"
