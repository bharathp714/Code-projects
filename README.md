#Requires -Version 5.1
<#
.SYNOPSIS
    Reports recent driver updates and reboot status for Intune-managed fleets and Nexthink Remote Actions.

.DESCRIPTION
    Intended for environments where **Microsoft Intune** > **Devices** > **Windows updates** > **Driver updates**
    (**Manage driver updates** / Windows driver update policies) approve driver packages in the admin center and
    **Windows Update** installs them on the device. This script does not call Intune Graph APIs; it reads only
    local OS state.

    Lightweight script (no external modules) that:
    - Reads device name from environment variables
    - Lists recent driver-related activity in the window (default 7 days): Win32_PnPSignedDriver catalog dates
      plus Windows Update Client Operational log (Event ID 19) for successful installs whose title matches
      driver/firmware heuristics (addresses Intune/WU installs where package DriverDate is older than the window)
    - Detects pending reboot via specified registry locations
    - Computes time since last boot from Win32_OperatingSystem
    - Emits a single JSON string suitable for Nexthink structured output

.NOTES
    Compatible: PowerShell 5.1+
    Execution: Standard user or SYSTEM; HKLM reads are required for registry checks.
    Intune correlation: Approval and assignment are in Intune; on-device rows reflect installed drivers (WMI), not the admin-center approval timestamp.
#>

[CmdletBinding()]
param(
    # Only include drivers whose DriverDate falls within this many days (0 = all with valid dates; default 7)
    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 365)]
    [int]$RecentDays = 7
)

# Stop on cmdlet errors; explicit try/catch around optional sections prevents hard failures.
$ErrorActionPreference = 'Stop'

#region Helper: WMI/CIM datetime to .NET DateTime
function ConvertTo-DateTimeFromWmi {
    param(
        [Parameter(ValueFromPipeline = $true)]
        $InputObject
    )
    process {
        if ($null -eq $InputObject) { return $null }
        if ($InputObject -is [datetime]) { return $InputObject }
        $s = [string]$InputObject
        if ([string]::IsNullOrWhiteSpace($s)) { return $null }
        try {
            return [System.Management.ManagementDateTimeConverter]::ToDateTime($s)
        }
        catch {
            return $null
        }
    }
}
#endregion

#region Supplement: Windows Update Client successful installs (Event ID 19)
# Win32_PnPSignedDriver.DriverDate is the *package/catalog* date, not when WU applied the update. Intune-approved
# drivers often install with an older DriverDate, so the WMI-only window can be empty. Operational log 19 records
# actual successful installs with the update title.
function Get-RecentWuDriverLikeSuccessEvents {
    param(
        [Parameter(Mandatory = $true)]
        [int]$RecentDays,
        [Parameter(Mandatory = $true)]
        [datetime]$CutoffUtc,
        [int]$MaxEvents = 2000
    )
    $rows = New-Object System.Collections.Generic.List[hashtable]
    if ($RecentDays -le 0) { return $rows }

    $startTime = (Get-Date).AddDays(-$RecentDays)
    try {
        $evts = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-WindowsUpdateClient/Operational'
            Id        = 19
            StartTime = $startTime
        } -MaxEvents $MaxEvents -ErrorAction Stop
    }
    catch {
        return $rows
    }

    # De-dupe by update title (case-insensitive); keep newest event per title.
    $bestByTitle = @{}

    foreach ($e in $evts) {
        $title = $null
        try {
            $xml = [xml]$e.ToXml()
            # EventData may contain one or many <Data> nodes; normalize to an array for PowerShell 5.1.
            $dataNodes = @()
            if ($null -ne $xml.Event.EventData -and $null -ne $xml.Event.EventData.Data) {
                $dataNodes = @($xml.Event.EventData.Data)
            }
            $node = $dataNodes | Where-Object { $_.Name -eq 'updateTitle' } | Select-Object -First 1
            if ($null -ne $node) { $title = [string]$node.'#text' }
        }
        catch { }

        if ([string]::IsNullOrWhiteSpace($title) -and $null -ne $e.Message) {
            if ($e.Message -match '(?i)the following update:\s*(.+)$') {
                $title = $matches[1].Trim()
            }
        }
        if ([string]::IsNullOrWhiteSpace($title)) { continue }

        # Heuristic: driver/firmware-class updates (tune for your catalog if needed).
        if ($title -notmatch '(?i)\bdriver\b|firmware|\bchipset\b|\bbios\b|\buefi\b|realtek|nvidia|geforce|radeon|\bamd\b|intel\(|qualcomm|mediatek|broadcom|marvell|synaptics|elan|touchpad|bluetooth|wireless|wlan|wi-?fi|network adapter|audio|sound|camera|fingerprint|display adapter|graphics|monitor|panel|sensor|trackpoint|lenovo system|\blenovo\b|thinkpad|thinkbook|hp firmware|dell firmware|surface firmware') {
            continue
        }

        $utc = $e.TimeCreated.ToUniversalTime()
        if ($utc -lt $CutoffUtc) { continue }

        $key = $title.ToLowerInvariant()
        if (-not $bestByTitle.ContainsKey($key) -or $utc -gt $bestByTitle[$key].TimeUtc) {
            $bestByTitle[$key] = [PSCustomObject]@{ TimeUtc = $utc; Title = $title; EventId = $e.Id }
        }
    }

    foreach ($k in $bestByTitle.Keys) {
        $rec = $bestByTitle[$k]
        $ver = 'Unknown'
        if ($rec.Title -match '\(([0-9][0-9.\s]*)\)') {
            $ver = $matches[1].Trim()
        }

        $rows.Add(@{
            DriverName            = $rec.Title
            DriverVersion         = $ver
            DriverInstallDate     = $rec.TimeUtc.ToString('o')
            Manufacturer          = $null
            DriverDetectionSource = 'WindowsUpdateClient_Event19_InstallSuccess'
            WindowsUpdateEventId  = $rec.EventId
        })
    }

    return $rows
}
#endregion

#region Device name from environment (per requirement)
$deviceName = $env:COMPUTERNAME
if ([string]::IsNullOrWhiteSpace($deviceName)) {
    $deviceName = 'Unknown'
}
#endregion

#region Time since last reboot (Win32_OperatingSystem.LastBootUpTime)
$lastBootUtc = $null
$timeSinceLastRebootHours = $null
$timeSinceLastRebootDays = $null
$timeSinceLastRebootDisplay = 'Unknown'
$lastBootUpTimeIso = $null

function Get-LastBootUpTimeUtc {
    # Prefer legacy WMI (Get-WmiObject): LastBootUpTime is a DMTF string — avoids CIM DateTime Kind quirks on some builds.
    $lastBootLocal = $null
    try {
        $wmiOs = Get-WmiObject -Class Win32_OperatingSystem -Property LastBootUpTime -ErrorAction Stop
        if ($null -ne $wmiOs -and $null -ne $wmiOs.LastBootUpTime) {
            $lastBootLocal = ConvertTo-DateTimeFromWmi -InputObject $wmiOs.LastBootUpTime
        }
    }
    catch {
        $lastBootLocal = $null
    }
    if ($null -eq $lastBootLocal) {
        try {
            $os = Get-CimInstance -Namespace root\cimv2 -ClassName Win32_OperatingSystem -Property LastBootUpTime -ErrorAction Stop
            if ($null -ne $os -and $null -ne $os.LastBootUpTime) {
                $raw = $os.LastBootUpTime
                if ($raw -is [datetime]) {
                    # CIM often returns Unspecified; treat as local wall-clock boot time (Win32_OperatingSystem convention).
                    switch ($raw.Kind) {
                        ([DateTimeKind]::Utc) { $lastBootLocal = $raw; break }
                        ([DateTimeKind]::Local) { $lastBootLocal = $raw; break }
                        Default { $lastBootLocal = [DateTime]::SpecifyKind($raw, [DateTimeKind]::Local); break }
                    }
                }
                else {
                    $lastBootLocal = ConvertTo-DateTimeFromWmi -InputObject $raw
                }
            }
        }
        catch {
            return $null
        }
    }
    if ($null -eq $lastBootLocal) { return $null }
    return $lastBootLocal.ToUniversalTime()
}

try {
    $lastBootUtc = Get-LastBootUpTimeUtc
    if ($null -ne $lastBootUtc) {
        $lastBootUpTimeIso = $lastBootUtc.ToString('o')
        $span = [datetime]::UtcNow - $lastBootUtc
        $timeSinceLastRebootHours = [math]::Round($span.TotalHours, 2)
        $timeSinceLastRebootDays = [math]::Round($span.TotalDays, 2)
        if ($span.TotalDays -ge 1) {
            $timeSinceLastRebootDisplay = ('{0} days ({1:F2} hours)' -f [int][math]::Floor($span.TotalDays), $span.TotalHours)
        }
        else {
            $timeSinceLastRebootDisplay = ('{0:F2} hours' -f $span.TotalHours)
        }
    }
}
catch {
    # Leave fields null/Unknown; script continues
}
#endregion

#region Reboot pending — registry checks (per requirement)
function Test-RegistryRebootPending {
    $reasons = New-Object System.Collections.Generic.List[string]

    # Component Based Servicing: presence of RebootPending key indicates pending reboot
    $cbsPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    try {
        if (Test-Path -LiteralPath $cbsPath) {
            [void]$reasons.Add('CBS_RebootPending')
        }
    }
    catch { /* ignore */ }

    # Windows Update: RebootRequired flag or subkey
    $wuAuto = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'
    try {
        if (Test-Path -LiteralPath $wuAuto) {
            $wuProps = Get-ItemProperty -LiteralPath $wuAuto -ErrorAction SilentlyContinue
            if ($null -ne $wuProps) {
                try {
                    if ([int]$wuProps.RebootRequired -eq 1) {
                        [void]$reasons.Add('WU_AutoUpdate_RebootRequired')
                    }
                }
                catch {
                    # Property missing or non-numeric; treat as not required.
                }
            }
        }
        $wuRebootKey = Join-Path $wuAuto 'RebootRequired'
        if (Test-Path -LiteralPath $wuRebootKey) {
            [void]$reasons.Add('WU_RebootRequired_Key')
        }
    }
    catch { /* ignore */ }

    # Pending file rename operations (pending reboot to apply)
    $smPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    try {
        $pfro = Get-ItemProperty -LiteralPath $smPath -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($null -ne $pfro) {
            $val = $pfro.PendingFileRenameOperations
            $hasContent = $false
            if ($val -is [string]) {
                $hasContent = -not [string]::IsNullOrWhiteSpace($val)
            }
            elseif ($val -is [array]) {
                $hasContent = $val.Count -gt 0
            }
            else {
                $hasContent = $null -ne $val
            }
            if ($hasContent) {
                [void]$reasons.Add('PendingFileRenameOperations')
            }
        }
    }
    catch { /* ignore */ }

    return [PSCustomObject]@{
        Pending = ($reasons.Count -gt 0)
        Reasons = $reasons
    }
}

$rebootInfo = $null
try {
    $rebootInfo = Test-RegistryRebootPending
}
catch {
    $rebootInfo = [PSCustomObject]@{ Pending = $false; Reasons = @() }
}

$rebootPendingText = if ($rebootInfo.Pending) { 'Yes' } else { 'No' }
#endregion

#region Recent drivers — Win32_PnPSignedDriver (DriverDate), optional window filter
# Intune "Manage driver updates" policies control which drivers Windows Update may install; after install,
# Win32_PnPSignedDriver reflects what is on box. DriverDate is the signed driver package date from the catalog (INF),
# a practical proxy for "recent driver activity," not a full audit log of install time (see SetupAPI/logs for that).
$driverRows = New-Object System.Collections.Generic.List[hashtable]
$cutoffUtc = $null
if ($RecentDays -gt 0) {
    $cutoffUtc = (Get-Date).ToUniversalTime().AddDays(-$RecentDays)
}

$allDrivers = @()
try {
    if ($RecentDays -gt 0) {
        # Fast path: push the date predicate into WMI/CIM to avoid enumerating every signed driver on large fleets.
        $cutoffLocal = (Get-Date).AddDays(-$RecentDays)
        $dmtf = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime($cutoffLocal)
        $wql = "SELECT DeviceName, DriverVersion, DriverDate, Manufacturer FROM Win32_PnPSignedDriver WHERE DriverDate >= '$dmtf'"
        $allDrivers = Get-CimInstance -Query $wql -ErrorAction Stop
    }
    else {
        # No time window: retrieve only needed properties (still enumerates all instances; use RecentDays > 0 when possible).
        $allDrivers = Get-CimInstance -Namespace root\cimv2 -ClassName Win32_PnPSignedDriver -Property DeviceName, DriverVersion, DriverDate, Manufacturer -ErrorAction Stop
    }
}
catch {
    try {
        # Fallback: full enumeration + in-process filter (slower but tolerant if WQL date comparison fails on a specific build).
        $allDrivers = Get-CimInstance -Namespace root\cimv2 -ClassName Win32_PnPSignedDriver -Property DeviceName, DriverVersion, DriverDate, Manufacturer -ErrorAction Stop
    }
    catch {
        $allDrivers = @()
    }
}

foreach ($d in $allDrivers) {
    $dt = ConvertTo-DateTimeFromWmi -InputObject $d.DriverDate
    if ($null -eq $dt) { continue }

    $dtUtc = $dt.ToUniversalTime()
    if ($null -ne $cutoffUtc -and $dtUtc -lt $cutoffUtc) { continue }

    $name = $d.DeviceName
    if ([string]::IsNullOrWhiteSpace($name)) { $name = 'Unknown' }

    $ver = $d.DriverVersion
    if ([string]::IsNullOrWhiteSpace($ver)) { $ver = 'Unknown' }

    $driverRows.Add(@{
        DriverName            = $name
        DriverVersion         = $ver
        DriverInstallDate     = $dtUtc.ToString('o')
        Manufacturer          = if ([string]::IsNullOrWhiteSpace($d.Manufacturer)) { $null } else { $d.Manufacturer }
        DriverDetectionSource = 'PnPSignedDriver_DriverDate'
        WindowsUpdateEventId  = $null
    })
}

# Add WU operational successes in the same window (install time, not INF package date).
try {
    if ($RecentDays -gt 0 -and $null -ne $cutoffUtc) {
        foreach ($wuRow in (Get-RecentWuDriverLikeSuccessEvents -RecentDays $RecentDays -CutoffUtc $cutoffUtc)) {
            $driverRows.Add($wuRow)
        }
    }
}
catch {
    # Log may be unavailable; continue with WMI-only results.
}

# Most recent first (clear ordering when multiple drivers match). @() ensures a single row stays an array (hashtable.Count is ambiguous).
try {
    $sorted = @(
        $driverRows | Sort-Object {
            [datetime]::Parse($_.DriverInstallDate, $null, [System.Globalization.DateTimeStyles]::RoundtripKind)
        } -Descending
    )
}
catch {
    $sorted = @($driverRows)
}
#endregion

#region Build result object — single structured payload for Nexthink
$mostRecentDriverDate = $null
if ($sorted.Count -gt 0) {
    $mostRecentDriverDate = $sorted[0].DriverInstallDate
}

$result = [ordered]@{
    DeviceName                          = $deviceName
    # Fixed string so Nexthink parsers and reports can document scope: Intune approves in cloud; WU installs; WMI lists drivers.
    IntuneDriverUpdatePolicyContext     = 'Drivers are approved/deployed via Intune Windows driver update policies (Manage driver updates); Windows Update installs locally. Recent rows combine Win32_PnPSignedDriver catalog dates with Windows Update Client Operational Event 19 install successes (title heuristics for driver/firmware-class updates). Not Intune Graph/admin-center data.'
    RebootPending                       = $rebootPendingText
    RebootPendingReasons                = @($rebootInfo.Reasons)
    TimeSinceLastRebootHours            = $timeSinceLastRebootHours
    TimeSinceLastRebootDays             = $timeSinceLastRebootDays
    TimeSinceLastRebootDisplay          = $timeSinceLastRebootDisplay
    LastBootUpTimeUtc                   = $lastBootUpTimeIso
    RecentDriverWindowDays              = $RecentDays
    MostRecentDriverInstallDateUtc      = $mostRecentDriverDate
    DriversUpdatedInWindow              = @($sorted)
    DriversUpdatedInWindowCount         = $sorted.Count
}

# Nexthink-friendly: one compressed JSON line (UTF-8 safe for typical ASCII field names)
try {
    $json = $result | ConvertTo-Json -Depth 6 -Compress
}
catch {
    $json = '{"Error":"Failed to serialize output"}'
}

Write-Output $json
#endregion
