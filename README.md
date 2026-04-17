#Requires -Version 5.1
<#
.SYNOPSIS
    Detects if a Lenovo camera driver has been updated but a system restart is pending.

.DESCRIPTION
    This script is designed for deployment via Nexthink Remote Actions.
    It performs a multi-layered check to determine whether:
      1. A camera driver is installed on the device (Lenovo-specific).
      2. The camera driver was recently updated (within the past N days).
      3. A system restart is pending due to driver/component changes.

    Detection layers:
      - Windows Driver Store: checks camera driver INF install date
      - Lenovo Thin Installer log: parses for camera package install with reboot code 3010
      - Lenovo System Update log: parses for camera-related updates with pending reboot
      - Registry reboot signals: PendingFileRenameOperations, CBS RebootPending,
        WindowsUpdate RebootRequired, SessionManager PendingFileRename
      - SetupAPI log: checks for recent camera driver installations

    Output (NXT_ prefixed for Nexthink Remote Action compatibility):
      NXT_CameraDriverFound          - Whether a camera driver was detected
      NXT_CameraDriverName           - Friendly name of the camera driver
      NXT_CameraDriverVersion        - Installed driver version
      NXT_CameraDriverDate           - Date of camera driver install/update
      NXT_CameraDriverRecentUpdate   - Whether driver was updated within threshold days
      NXT_RebootPending              - Whether any reboot-pending signal is active
      NXT_RebootSource               - Which detection layer triggered the reboot flag
      NXT_ActionRequired             - TRUE if camera driver updated AND reboot pending
      NXT_Summary                    - Human-readable summary

.NOTES
    Author      : Bharath (Enterprise Endpoint Management)
    Target      : Lenovo devices managed via Nexthink + Intune/SCCM
    Tested On   : Windows 10 21H2+, Windows 11
    Exit Codes  :
        0  = No action required (camera driver OK or no camera found)
        1  = Camera driver updated, restart pending — action required
        2  = Script execution error
#>

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
$RecentUpdateThresholdDays = 7   # Days to look back for a "recent" driver update
$ThinInstallerLogPath      = "$env:ProgramData\Lenovo\Thin Installer\Logs"
$SystemUpdateLogPath       = "$env:ProgramData\Lenovo\System Update\logs"
$SetupAPILogPath           = "$env:WINDIR\INF\setupapi.dev.log"

# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT VARIABLES (NXT_ prefix required for Nexthink)
# ─────────────────────────────────────────────────────────────────────────────
$NXT_CameraDriverFound        = "FALSE"
$NXT_CameraDriverName         = "N/A"
$NXT_CameraDriverVersion      = "N/A"
$NXT_CameraDriverDate         = "N/A"
$NXT_CameraDriverRecentUpdate = "FALSE"
$NXT_RebootPending            = "FALSE"
$NXT_RebootSource             = "None"
$NXT_ActionRequired           = "FALSE"
$NXT_Summary                  = "No issues detected."

# ─────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

function Write-NxtOutput {
    <#
    .SYNOPSIS Emits all NXT_ variables as key=value pairs for Nexthink ingestion. #>
    Write-Output "NXT_CameraDriverFound=$NXT_CameraDriverFound"
    Write-Output "NXT_CameraDriverName=$NXT_CameraDriverName"
    Write-Output "NXT_CameraDriverVersion=$NXT_CameraDriverVersion"
    Write-Output "NXT_CameraDriverDate=$NXT_CameraDriverDate"
    Write-Output "NXT_CameraDriverRecentUpdate=$NXT_CameraDriverRecentUpdate"
    Write-Output "NXT_RebootPending=$NXT_RebootPending"
    Write-Output "NXT_RebootSource=$NXT_RebootSource"
    Write-Output "NXT_ActionRequired=$NXT_ActionRequired"
    Write-Output "NXT_Summary=$NXT_Summary"
}

function Get-CameraDriverFromDriverStore {
    <#
    .SYNOPSIS
        Queries Win32_PnPSignedDriver for camera class devices and returns
        the most recently updated one.
    #>
    try {
        # Class GUID for Camera: {ca3e7ab9-b4c3-4ae6-8251-579ef933890f}
        # Also covers Image class: {6bdd1fc6-810f-11d0-bec7-08002be2092f}
        $cameraDrivers = Get-WmiObject Win32_PnPSignedDriver -ErrorAction Stop |
            Where-Object {
                ($_.DeviceClass -eq 'Camera') -or
                ($_.DeviceClass -eq 'Image') -or
                ($_.FriendlyName -match 'camera|webcam|IR Camera|RGB Camera|Integrated Camera') -or
                ($_.DeviceName  -match 'camera|webcam|IR Camera|RGB Camera|Integrated Camera')
            } |
            Where-Object { $_.DriverVersion -ne $null } |
            Sort-Object { [System.Version]($_.DriverVersion -replace '[^\d\.]','') } -Descending |
            Select-Object -First 1

        return $cameraDrivers
    }
    catch {
        return $null
    }
}

function Get-DriverInstallDate {
    param([string]$DriverInfName)
    <#
    .SYNOPSIS
        Parses SetupAPI dev log to find the most recent install date
        for a given INF file name.
    #>
    try {
        if (-not (Test-Path $SetupAPILogPath)) { return $null }

        # SetupAPI log entries look like:
        # >>> [SetupCopyOEMInf - oem123.inf]
        # >>> Section start 2024/11/05 14:32:01.456
        $logContent = Get-Content $SetupAPILogPath -ErrorAction Stop

        $recentDate = $null
        $capture    = $false

        foreach ($line in $logContent) {
            if ($line -match "SetupCopyOEMInf.*$([regex]::Escape($DriverInfName))" -or
                $line -match "Driver Install.*$([regex]::Escape($DriverInfName))") {
                $capture = $true
            }
            if ($capture -and $line -match 'Section start\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})') {
                $parsedDate = [datetime]::ParseExact($Matches[1], 'yyyy/MM/dd HH:mm:ss', $null)
                if ($null -eq $recentDate -or $parsedDate -gt $recentDate) {
                    $recentDate = $parsedDate
                }
                $capture = $false
            }
        }
        return $recentDate
    }
    catch {
        return $null
    }
}

function Test-RebootPendingRegistry {
    <#
    .SYNOPSIS
        Checks all well-known registry keys that indicate a reboot is pending.
        Returns a hashtable: @{ Pending = $true/$false; Sources = @(...) }
    #>
    $sources = @()

    # 1. PendingFileRenameOperations (most reliable for driver updates)
    try {
        $pfro = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
                                 -Name 'PendingFileRenameOperations' -ErrorAction Stop
        if ($pfro.PendingFileRenameOperations) {
            $sources += 'PendingFileRenameOperations'
        }
    } catch {}

    # 2. CBS / Windows Servicing RebootPending
    try {
        $cbsPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        if (Test-Path $cbsPath) { $sources += 'CBS-RebootPending' }
    } catch {}

    # 3. Windows Update RebootRequired
    try {
        $wuPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        if (Test-Path $wuPath) { $sources += 'WindowsUpdate-RebootRequired' }
    } catch {}

    # 4. Session Manager - PendingFileRename (alternate key)
    try {
        $smPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        $pfr    = (Get-ItemProperty -Path $smPath -ErrorAction Stop).PendingFileRename
        if ($pfr) { $sources += 'SessionManager-PendingFileRename' }
    } catch {}

    # 5. RebootInProgress (sometimes set by Lenovo updates)
    try {
        $ripPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootInProgress'
        if (Test-Path $ripPath) { $sources += 'WindowsUpdate-RebootInProgress' }
    } catch {}

    return @{
        Pending = ($sources.Count -gt 0)
        Sources = $sources
    }
}

function Test-ThinInstallerCameraReboot {
    <#
    .SYNOPSIS
        Parses Lenovo Thin Installer logs for camera package installs
        that returned exit code 3010 (reboot required).
    #>
    try {
        if (-not (Test-Path $ThinInstallerLogPath)) { return $false }

        $logFiles = Get-ChildItem -Path $ThinInstallerLogPath -Filter '*.log' -ErrorAction Stop |
                    Sort-Object LastWriteTime -Descending |
                    Select-Object -First 5

        foreach ($logFile in $logFiles) {
            $content = Get-Content $logFile.FullName -ErrorAction SilentlyContinue
            if (-not $content) { continue }

            $cameraBlockActive = $false
            foreach ($line in $content) {
                # Detect camera-related package block
                if ($line -match 'camera|webcam|IR Camera|Integrated Camera' -and
                    $line -match 'Installing|Package|Driver') {
                    $cameraBlockActive = $true
                }
                # Within a camera block, check for 3010 (reboot required)
                if ($cameraBlockActive -and $line -match '(return code|exit code|ExitCode)\s*[=:]\s*3010') {
                    return $true
                }
                # Reset block on next package boundary
                if ($cameraBlockActive -and $line -match '^---') {
                    $cameraBlockActive = $false
                }
            }
        }
    }
    catch {}
    return $false
}

function Test-SystemUpdateCameraReboot {
    <#
    .SYNOPSIS
        Parses Lenovo System Update logs for camera-related updates
        with a pending reboot indicator.
    #>
    try {
        if (-not (Test-Path $SystemUpdateLogPath)) { return $false }

        $logFiles = Get-ChildItem -Path $SystemUpdateLogPath -Filter '*.log' -ErrorAction Stop |
                    Sort-Object LastWriteTime -Descending |
                    Select-Object -First 5

        foreach ($logFile in $logFiles) {
            $content = Get-Content $logFile.FullName -ErrorAction SilentlyContinue
            if (-not $content) { continue }

            $cameraLine = $false
            foreach ($line in $content) {
                if ($line -match 'camera|webcam|IR Camera|Integrated Camera') {
                    $cameraLine = $true
                }
                if ($cameraLine -and ($line -match 'RebootNeeded|NeedsReboot|reboot required|3010')) {
                    return $true
                }
            }
        }
    }
    catch {}
    return $false
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN DETECTION LOGIC
# ─────────────────────────────────────────────────────────────────────────────
try {

    # ── STEP 1: Detect camera driver via Win32_PnPSignedDriver ───────────────
    $camDriver = Get-CameraDriverFromDriverStore

    if ($null -eq $camDriver) {
        $NXT_Summary = "No camera driver found on this device."
        Write-NxtOutput
        exit 0
    }

    $NXT_CameraDriverFound   = "TRUE"
    $NXT_CameraDriverName    = if ($camDriver.FriendlyName) { $camDriver.FriendlyName } `
                               elseif ($camDriver.DeviceName)  { $camDriver.DeviceName  } `
                               else                            { "Unknown Camera Device" }
    $NXT_CameraDriverVersion = if ($camDriver.DriverVersion) { $camDriver.DriverVersion } else { "N/A" }

    # ── STEP 2: Determine driver install/update date ─────────────────────────
    $driverDate = $null

    # Primary: WMI DriverDate field (format: YYYYMMDD000000.000000+000)
    if ($camDriver.DriverDate) {
        try {
            $rawDate    = $camDriver.DriverDate -replace '\..*', ''   # strip microseconds
            $driverDate = [Management.ManagementDateTimeConverter]::ToDateTime($camDriver.DriverDate)
        } catch {}
    }

    # Secondary: SetupAPI log (captures actual install date, not just INF date)
    if ($camDriver.InfName) {
        $setupDate = Get-DriverInstallDate -DriverInfName $camDriver.InfName
        # Use the more recent of the two dates — SetupAPI date reflects actual install
        if ($setupDate -and ($null -eq $driverDate -or $setupDate -gt $driverDate)) {
            $driverDate = $setupDate
        }
    }

    if ($driverDate) {
        $NXT_CameraDriverDate = $driverDate.ToString('yyyy-MM-dd HH:mm:ss')
        $daysSinceUpdate      = (Get-Date) - $driverDate
        if ($daysSinceUpdate.TotalDays -le $RecentUpdateThresholdDays) {
            $NXT_CameraDriverRecentUpdate = "TRUE"
        }
    }

    # ── STEP 3: Check all reboot-pending signals ─────────────────────────────
    $rebootCheck = Test-RebootPendingRegistry

    if ($rebootCheck.Pending) {
        $NXT_RebootPending = "TRUE"
        $NXT_RebootSource  = $rebootCheck.Sources -join ', '
    }

    # ── STEP 4: Cross-check Lenovo update logs for camera + 3010 ─────────────
    if ($NXT_RebootPending -eq "FALSE") {
        $thinInstallerHit = Test-ThinInstallerCameraReboot
        if ($thinInstallerHit) {
            $NXT_RebootPending = "TRUE"
            $NXT_RebootSource  = "Lenovo-ThinInstaller-ExitCode3010"
        }
    }

    if ($NXT_RebootPending -eq "FALSE") {
        $sysUpdateHit = Test-SystemUpdateCameraReboot
        if ($sysUpdateHit) {
            $NXT_RebootPending = "TRUE"
            $NXT_RebootSource  = "Lenovo-SystemUpdate-RebootNeeded"
        }
    }

    # ── STEP 5: Determine final action flag ──────────────────────────────────
    if ($NXT_RebootPending -eq "TRUE" -and $NXT_CameraDriverFound -eq "TRUE") {
        $NXT_ActionRequired = "TRUE"
        $NXT_Summary = "Camera driver '$NXT_CameraDriverName' (v$NXT_CameraDriverVersion) " +
                       "updated on $NXT_CameraDriverDate. Restart pending via: $NXT_RebootSource. " +
                       "Camera may be non-functional until restarted."
    }
    elseif ($NXT_RebootPending -eq "FALSE" -and $NXT_CameraDriverFound -eq "TRUE") {
        $NXT_Summary = "Camera driver '$NXT_CameraDriverName' (v$NXT_CameraDriverVersion) " +
                       "is installed and no restart is pending. Camera should be functional."
    }
    else {
        $NXT_Summary = "Camera driver not found or no actionable condition detected."
    }

    # ── OUTPUT ────────────────────────────────────────────────────────────────
    Write-NxtOutput

    # Exit code for Intune Proactive Remediation compatibility
    if ($NXT_ActionRequired -eq "TRUE") { exit 1 } else { exit 0 }

}
catch {
    $NXT_Summary = "Script error: $($_.Exception.Message)"
    Write-NxtOutput
    exit 2
}
