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
    - Lists drivers with recent Win32_PnPSignedDriver DriverDate values (default window 7 days)
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

try {
    $os = Get-CimInstance -Namespace root\cimv2 -ClassName Win32_OperatingSystem -Property LastBootUpTime -ErrorAction Stop
    if ($null -ne $os -and $null -ne $os.LastBootUpTime) {
        $lastBootLocal = ConvertTo-DateTimeFromWmi -InputObject $os.LastBootUpTime
        if ($null -ne $lastBootLocal) {
            $lastBootUtc = $lastBootLocal.ToUniversalTime()
            $lastBootUpTimeIso = $lastBootUtc.ToString('o')
            # Compare in UTC so DST / locale do not skew uptime math.
            $span = (Get-Date).ToUniversalTime() - $lastBootUtc
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
        DriverName        = $name
        DriverVersion     = $ver
        DriverInstallDate = $dtUtc.ToString('o')
        Manufacturer      = if ([string]::IsNullOrWhiteSpace($d.Manufacturer)) { $null } else { $d.Manufacturer }
    })
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
    IntuneDriverUpdatePolicyContext     = 'Drivers are approved/deployed via Intune Windows driver update policies (Manage driver updates); Windows Update installs drivers locally. This output is on-device inventory (WMI) only, not Intune service data.'
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
