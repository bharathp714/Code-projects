#Requires -Version 5.1
# Encoding: UTF-8 with BOM (required by Nexthink Remote Actions)
<#
.SYNOPSIS
    Lenovo Camera Driver — Detect Reboot Pending and Notify User via Engage.

.DESCRIPTION
    Single Nexthink Remote Action that combines detection and campaign notification:

      PHASE 1 — DETECTION:
        Determines whether a Lenovo camera driver has been updated but the device
        has not yet been restarted to activate it. Uses a multi-layer approach:
          - PnP Health Gate: Win32_PnPEntity ConfigManagerErrorCode checked first.
            ErrorCode=0 means driver already healthy — exits immediately with
            ActionRequired=false, preventing false positives after a restart.
          - PFRO: PendingFileRenameOperations parsed entry-by-entry; only entries
            whose file paths reference camera keywords/driver version count.
          - Lenovo Thin Installer log: camera package exit code 3010.
          - Lenovo System Update log: camera RebootNeeded flag.
          - Date resolution: DriverStore staging time, SetupAPI log, OEM INF
            DriverVer, WMI DriverDate — picks newest valid date (>=2020),
            discarding legacy placeholder dates (e.g. 2006).

      PHASE 2 — CAMPAIGN (only runs if ActionRequired=true):
        Loads nxtcampaignaction.dll and fires the Engage notification campaign
        specified by CampaignNqlId. Waits up to CampaignTimeoutSeconds for the
        user to respond. Optionally initiates a graceful restart if the user
        clicks "Restart Now" and EnableAutoRestart is set to true.

    All outputs are written via [Nxt]:: methods — Nexthink auto-detects them at
    import time and lists them in the Outputs section of the Remote Action console.
    Input parameters are declared in the param() block — Nexthink auto-detects
    them and lists them in the Parameters section.

.NOTES
    Author      : Bharath (Enterprise Endpoint Management)
    Target      : Lenovo devices — Nexthink Infinity + Intune/SCCM
    Requires    : Nexthink Collector, nxtremoteactions.dll, nxtcampaignaction.dll
                  Nexthink Act + Engage licences
    Encoding    : UTF-8 with BOM
    Exit Codes  :
        0 = No action required (driver healthy or no camera found)
        1 = Action required — camera restart pending (campaign fired or failed)
        2 = Script execution error
#>

# ─────────────────────────────────────────────────────────────────────────────
# INPUT PARAMETERS
# param() MUST be the first executable block — Nexthink scans this to populate
# the Parameters section in the Remote Action console automatically.
# ─────────────────────────────────────────────────────────────────────────────
param(
    # NQL ID of the published Nexthink Engage campaign.
    # Get it from: Nexthink Infinity → Engage → Campaigns → right-click → Copy NQL ID
    # Format: campaign:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    [string]$CampaignNqlId = "",

    # Seconds to wait for the user to respond to the campaign before timing out.
    # Recommended range: 180-600. Default: 300 (5 minutes).
    [string]$CampaignTimeoutSeconds = "300",

    # Set to "true" to initiate a graceful 60-second restart when the user
    # clicks "Restart Now" in the campaign. Default: "false" (notify only).
    [string]$EnableAutoRestart = "false",

    # Days to look back for a "recent" camera driver update.
    # Only used for the CameraDriverRecentUpdate output flag. Default: 7.
    [string]$RecentUpdateThresholdDays = "7"
)

# ─────────────────────────────────────────────────────────────────────────────
# DEFAULT ERROR HANDLER
# Placed before Add-Type so unhandled exceptions are always surfaced.
# ─────────────────────────────────────────────────────────────────────────────
trap {
    $host.ui.WriteErrorLine($_.ToString())
    exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# LOAD NEXTHINK ASSEMBLIES
# nxtremoteactions.dll  — [Nxt]:: output methods, auto-detected on import
# nxtcampaignaction.dll — [Nxt.CampaignAction]:: campaign methods
# ─────────────────────────────────────────────────────────────────────────────
Add-Type -Path "$env:NEXTHINK\RemoteActions\nxtremoteactions.dll"  -ErrorAction Stop
Add-Type -Path "$env:NEXTHINK\RemoteActions\nxtcampaignaction.dll" -ErrorAction Stop

# ─────────────────────────────────────────────────────────────────────────────
# INTERNAL CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
$ThinInstallerLogPath = "$env:ProgramData\Lenovo\Thin Installer\Logs"
$SystemUpdateLogPath  = "$env:ProgramData\Lenovo\System Update\logs"
$SetupAPILogPath      = "$env:WINDIR\INF\setupapi.dev.log"

# Parse input parameters to correct types
$thresholdDays = 7
$timeoutSecs   = 300
$autoRestart   = $false
try { $thresholdDays = [int]$RecentUpdateThresholdDays }              catch {}
try { $timeoutSecs   = [int]$CampaignTimeoutSeconds }                 catch {}
try { $autoRestart   = [System.Convert]::ToBoolean($EnableAutoRestart) } catch {}

# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT VARIABLE DEFAULTS
# IMPORTANT: Never pass uppercase string "TRUE"/"FALSE" to WriteOutputBool —
# use native $true/$false. Nexthink known bug: uppercase terminates the process.
# ─────────────────────────────────────────────────────────────────────────────
$out_CameraDriverFound        = $false
$out_CameraDriverName         = "N/A"
$out_CameraDriverVersion      = "N/A"
$out_CameraDriverDate         = "N/A"
$out_CameraDriverRecentUpdate = $false
$out_RebootPending            = $false
$out_RebootSource             = "None"
$out_HealthCheckResult        = "Not-Run"
$out_ActionRequired           = $false
$out_CampaignStatus           = "not_run"
$out_UserResponse             = "N/A"
$out_RestartInitiated         = $false
$out_Summary                  = "No issues detected."

# ─────────────────────────────────────────────────────────────────────────────
# WRITE ALL OUTPUTS TO NEXTHINK DATA LAYER
# Nexthink scans these [Nxt]:: calls at import to auto-populate the Outputs
# section. All 13 outputs will appear in the Remote Action console.
# ─────────────────────────────────────────────────────────────────────────────
function Write-NxtOutput {
    [Nxt]::WriteOutputBool(  "CameraDriverFound",        $out_CameraDriverFound)
    [Nxt]::WriteOutputString("CameraDriverName",         $out_CameraDriverName)
    [Nxt]::WriteOutputString("CameraDriverVersion",      $out_CameraDriverVersion)
    [Nxt]::WriteOutputString("CameraDriverDate",         $out_CameraDriverDate)
    [Nxt]::WriteOutputBool(  "CameraDriverRecentUpdate", $out_CameraDriverRecentUpdate)
    [Nxt]::WriteOutputBool(  "RebootPending",            $out_RebootPending)
    [Nxt]::WriteOutputString("RebootSource",             $out_RebootSource)
    [Nxt]::WriteOutputString("HealthCheckResult",        $out_HealthCheckResult)
    [Nxt]::WriteOutputBool(  "ActionRequired",           $out_ActionRequired)
    [Nxt]::WriteOutputString("CampaignStatus",           $out_CampaignStatus)
    [Nxt]::WriteOutputString("UserResponse",             $out_UserResponse)
    [Nxt]::WriteOutputBool(  "RestartInitiated",         $out_RestartInitiated)
    [Nxt]::WriteOutputString("Summary",                  $out_Summary)
}

# ═════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS — DETECTION
# ═════════════════════════════════════════════════════════════════════════════

function Get-CameraDriverFromDriverStore {
    try {
        $cameraDrivers = Get-WmiObject Win32_PnPSignedDriver -ErrorAction Stop |
            Where-Object {
                ($_.DeviceClass -eq 'Camera') -or
                ($_.DeviceClass -eq 'Image')  -or
                ($_.FriendlyName -match 'camera|webcam|IR Camera|RGB Camera|Integrated Camera') -or
                ($_.DeviceName   -match 'camera|webcam|IR Camera|RGB Camera|Integrated Camera')
            } |
            Where-Object { $_.DriverVersion -ne $null } |
            Sort-Object { [System.Version]($_.DriverVersion -replace '[^\d\.]', '') } -Descending |
            Select-Object -First 1
        return $cameraDrivers
    }
    catch { return $null }
}

function Get-DriverInstallDate {
    param([string]$DriverInfName)
    try {
        if (-not (Test-Path $SetupAPILogPath)) { return $null }
        $logContent = Get-Content $SetupAPILogPath -Raw -ErrorAction Stop
        $recentDate = $null
        $searchPatterns = @(
            [regex]::Escape($DriverInfName),
            'Camera\s+DFU', 'Integrated\s+Camera', 'IR\s+Camera', 'RGB\s+Camera', 'Webcam'
        )
        foreach ($pattern in $searchPatterns) {
            $blockMatches = [regex]::Matches(
                $logContent,
                "(?s)(?:SetupCopyOEMInf|Driver\s+Install|Device\s+Install)[^\n]*$pattern[^\n]*\n(?:.*?\n){0,20}?Section\s+start\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})",
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
            )
            foreach ($m in $blockMatches) {
                try {
                    $parsedDate = [datetime]::ParseExact($m.Groups[1].Value, 'yyyy/MM/dd HH:mm:ss', $null)
                    if ($null -eq $recentDate -or $parsedDate -gt $recentDate) { $recentDate = $parsedDate }
                } catch {}
            }
        }
        return $recentDate
    }
    catch { return $null }
}

function Get-OemInfDriverDate {
    param([string]$DriverVersion, [string]$DriverInfName)
    $infDir  = "$env:WINDIR\INF"
    $cutoff  = [datetime]'2020-01-01'

    function Parse-DriverVer([string]$infPath) {
        try {
            foreach ($line in (Get-Content $infPath -ErrorAction Stop)) {
                if ($line -match '^\s*DriverVer\s*=\s*(\d{1,2}/\d{1,2}/\d{4})\s*,') {
                    return [datetime]::ParseExact($Matches[1].Trim(), 'MM/dd/yyyy', $null)
                }
            }
        } catch {}
        return $null
    }

    $bestDate = $null
    if ($DriverInfName) {
        $exactPath = Join-Path $infDir $DriverInfName
        if (Test-Path $exactPath) { $bestDate = Parse-DriverVer $exactPath }
    }

    if ($null -eq $bestDate -or $bestDate -lt $cutoff) {
        try {
            foreach ($inf in (Get-ChildItem -Path $infDir -Filter 'oem*.inf' -ErrorAction Stop)) {
                $content = Get-Content $inf.FullName -Raw -ErrorAction SilentlyContinue
                if (-not $content) { continue }
                $isMatch = ($DriverVersion -and $content -match [regex]::Escape($DriverVersion)) -or
                           ($content -match 'Camera\s+DFU|Integrated\s+Camera|IR\s+Camera|RGB\s+Camera|Webcam')
                if (-not $isMatch) { continue }
                $candidate = Parse-DriverVer $inf.FullName
                if ($candidate -and $candidate -ge $cutoff) {
                    if ($null -eq $bestDate -or $candidate -gt $bestDate) { $bestDate = $candidate }
                }
            }
        } catch {}
    }
    return $bestDate
}

function Get-DriverStoreStagingDate {
    param([string]$DriverVersion, [string]$DriverInfName)
    try {
        $repoBase = "$env:WINDIR\System32\DriverStore\FileRepository"
        if (-not (Test-Path $repoBase)) { return $null }
        $infStem    = if ($DriverInfName) { [IO.Path]::GetFileNameWithoutExtension($DriverInfName) } else { '' }
        $candidates = Get-ChildItem -Path $repoBase -Directory -ErrorAction Stop |
            Where-Object {
                ($infStem -and $_.Name -match [regex]::Escape($infStem)) -or
                ($_.Name -match 'camera|webcam|ir_camera|rgb_camera|ivcam|cameradfu|camera_dfu')
            } | Sort-Object LastWriteTime -Descending
        foreach ($folder in $candidates) {
            $infFiles = Get-ChildItem -Path $folder.FullName -Filter '*.inf' -ErrorAction SilentlyContinue
            foreach ($inf in $infFiles) {
                $content = Get-Content $inf.FullName -Raw -ErrorAction SilentlyContinue
                if ($DriverVersion -and $content -match [regex]::Escape($DriverVersion)) { return $folder.LastWriteTime }
                if ($content -match 'Camera\s+DFU|Integrated\s+Camera|IR\s+Camera') { return $folder.LastWriteTime }
            }
        }
        if ($candidates) { return $candidates[0].LastWriteTime }
    }
    catch {}
    return $null
}

function Test-CameraDriverHealthy {
    param([string]$DriverVersion, [string]$InfName)

    $rebootNeededCodes = @(1, 10, 14, 18, 21, 28, 43)

    # Check 1: Win32_PnPEntity ConfigManagerErrorCode
    try {
        $pnpDevices = Get-WmiObject Win32_PnPEntity -ErrorAction Stop |
            Where-Object {
                ($_.PNPClass -eq 'Camera') -or ($_.PNPClass -eq 'Image') -or
                ($_.Name        -match 'camera|webcam|IR Camera|RGB Camera|Integrated Camera') -or
                ($_.Description -match 'camera|webcam|IR Camera|RGB Camera|Integrated Camera')
            }
        foreach ($dev in $pnpDevices) {
            $code = $dev.ConfigManagerErrorCode
            if ($code -eq 0)                      { return @{ Healthy = $true;  Reason = "PnP-DeviceOK (ErrorCode=0, Device='$($dev.Name)')" } }
            if ($code -in $rebootNeededCodes)      { return @{ Healthy = $false; Reason = "PnP-DeviceError (ErrorCode=$code, Device='$($dev.Name)') restart still required" } }
        }
    } catch {}

    # Check 2: CIM fallback
    try {
        $cimDevices = Get-CimInstance Win32_PnPEntity -ErrorAction Stop |
            Where-Object { ($_.PNPClass -in @('Camera','Image')) -or ($_.Name -match 'camera|webcam|IR Camera|RGB Camera|Integrated Camera') }
        foreach ($dev in $cimDevices) {
            if ($dev.ConfigManagerErrorCode -eq 0) { return @{ Healthy = $true; Reason = "CIM-DeviceOK (ErrorCode=0, Device='$($dev.Name)')" } }
        }
    } catch {}

    # Check 3: Service registry active image path
    try {
        if ($DriverVersion -and $InfName) {
            $infStem    = [IO.Path]::GetFileNameWithoutExtension($InfName)
            $driverKeys = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction Stop |
                Where-Object { $_.Name -match $infStem -or $_.PSChildName -match 'camera|ivcam|usbvideo' }
            foreach ($key in $driverKeys) {
                $imgPath = (Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue).ImagePath
                if ($imgPath) { return @{ Healthy = $true; Reason = "ServiceRegistry-DriverActive (key='$($key.PSChildName)')" } }
            }
        }
    } catch {}

    return @{ Healthy = $false; Reason = "HealthCheck-Inconclusive" }
}

function Test-CameraRebootPendingRegistry {
    param(
        [string]$DriverVersion,
        [string]$DriverInfName,
        [string]$DriverStoreFolder
    )
    $cameraKeywords = @('camera','webcam','ivcam','cameradfu','camera_dfu','ircamera','ir_camera','rgbcamera','rgb_camera')
    $infStem        = if ($DriverInfName) { [IO.Path]::GetFileNameWithoutExtension($DriverInfName) } else { '' }

    try {
        $pfro = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop).PendingFileRenameOperations
        if ($pfro) {
            foreach ($entry in $pfro) {
                if (-not $entry) { continue }
                $entryLower = $entry.ToLower()
                if ($cameraKeywords | Where-Object { $entryLower -match $_ })                                      { return @{ Pending = $true; Source = "PFRO-CameraKeyword: $entry" } }
                if ($DriverVersion -and $entryLower -match [regex]::Escape($DriverVersion))                        { return @{ Pending = $true; Source = "PFRO-DriverVersion: $entry" } }
                if ($infStem       -and $entryLower -match [regex]::Escape($infStem.ToLower()))                    { return @{ Pending = $true; Source = "PFRO-InfName: $entry" } }
                if ($DriverStoreFolder -and $entryLower -match [regex]::Escape($DriverStoreFolder.ToLower()))      { return @{ Pending = $true; Source = "PFRO-DriverStoreFolder: $entry" } }
            }
        }
    } catch {}

    return @{ Pending = $false; Source = "None" }
}

function Test-ThinInstallerCameraReboot {
    try {
        if (-not (Test-Path $ThinInstallerLogPath)) { return $false }
        $logFiles = Get-ChildItem -Path $ThinInstallerLogPath -Filter '*.log' -ErrorAction Stop |
            Sort-Object LastWriteTime -Descending | Select-Object -First 5
        foreach ($logFile in $logFiles) {
            $content = Get-Content $logFile.FullName -ErrorAction SilentlyContinue
            if (-not $content) { continue }
            $cameraActive = $false
            foreach ($line in $content) {
                if ($line -match 'camera|webcam|IR Camera|Integrated Camera' -and $line -match 'Installing|Package|Driver') { $cameraActive = $true }
                if ($cameraActive -and $line -match '(return code|exit code|ExitCode)\s*[=:]\s*3010') { return $true }
                if ($cameraActive -and $line -match '^---') { $cameraActive = $false }
            }
        }
    } catch {}
    return $false
}

function Test-SystemUpdateCameraReboot {
    try {
        if (-not (Test-Path $SystemUpdateLogPath)) { return $false }
        $logFiles = Get-ChildItem -Path $SystemUpdateLogPath -Filter '*.log' -ErrorAction Stop |
            Sort-Object LastWriteTime -Descending | Select-Object -First 5
        foreach ($logFile in $logFiles) {
            $content = Get-Content $logFile.FullName -ErrorAction SilentlyContinue
            if (-not $content) { continue }
            $cameraLine = $false
            foreach ($line in $content) {
                if ($line -match 'camera|webcam|IR Camera|Integrated Camera') { $cameraLine = $true }
                if ($cameraLine -and $line -match 'RebootNeeded|NeedsReboot|reboot required|3010') { return $true }
            }
        }
    } catch {}
    return $false
}

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 1 — DETECTION
# ═════════════════════════════════════════════════════════════════════════════
try {

    # ── Step 1: Find camera driver ────────────────────────────────────────────
    $camDriver = Get-CameraDriverFromDriverStore

    if ($null -eq $camDriver) {
        $out_Summary = "No camera driver found on this device."
        Write-NxtOutput
        exit 0
    }

    $out_CameraDriverFound   = $true
    $out_CameraDriverName    = if ($camDriver.FriendlyName) { $camDriver.FriendlyName }
                               elseif ($camDriver.DeviceName) { $camDriver.DeviceName }
                               else { "Unknown Camera Device" }
    $out_CameraDriverVersion = if ($camDriver.DriverVersion) { $camDriver.DriverVersion } else { "N/A" }

    # ── Step 2: Resolve driver date (multi-source, newest valid >= 2020 wins) ─
    $dateCutoff     = [datetime]'2020-01-01'
    $dateCandidates = [System.Collections.Generic.List[hashtable]]::new()

    $storeDate  = Get-DriverStoreStagingDate -DriverVersion $camDriver.DriverVersion -DriverInfName $camDriver.InfName
    $setupDate  = Get-DriverInstallDate      -DriverInfName $camDriver.InfName
    $oemInfDate = Get-OemInfDriverDate       -DriverVersion $camDriver.DriverVersion -DriverInfName $camDriver.InfName

    if ($storeDate  -and $storeDate  -ge $dateCutoff) { $dateCandidates.Add(@{ Date = $storeDate;  Source = 'DriverStore-Staging' }) }
    if ($setupDate  -and $setupDate  -ge $dateCutoff) { $dateCandidates.Add(@{ Date = $setupDate;  Source = 'SetupAPI-Log' }) }
    if ($oemInfDate -and $oemInfDate -ge $dateCutoff) { $dateCandidates.Add(@{ Date = $oemInfDate; Source = 'OemInf-DriverVer' }) }

    if ($camDriver.DriverDate) {
        try {
            $wmiDate = [Management.ManagementDateTimeConverter]::ToDateTime($camDriver.DriverDate)
            if ($wmiDate -and $wmiDate -ge $dateCutoff) { $dateCandidates.Add(@{ Date = $wmiDate; Source = 'WMI-DriverDate' }) }
        } catch {}
    }

    $bestEntry  = $dateCandidates | Sort-Object { $_.Date } -Descending | Select-Object -First 1
    $driverDate = if ($bestEntry) { $bestEntry.Date } else { $null }

    if ($driverDate) {
        $out_CameraDriverDate = "$($driverDate.ToString('yyyy-MM-dd HH:mm:ss')) [$($bestEntry.Source)]"
        if (((Get-Date) - $driverDate).TotalDays -le $thresholdDays) { $out_CameraDriverRecentUpdate = $true }
    }

    # ── Step 3: DriverStore folder path (used by PFRO check) ─────────────────
    $cameraStoreFolder = ''
    try {
        $infStem   = if ($camDriver.InfName) { [IO.Path]::GetFileNameWithoutExtension($camDriver.InfName) } else { '' }
        $candidate = Get-ChildItem "$env:WINDIR\System32\DriverStore\FileRepository" -Directory -ErrorAction Stop |
            Where-Object { ($infStem -and $_.Name -match [regex]::Escape($infStem)) -or ($_.Name -match 'camera|webcam|ir_camera|rgb_camera|ivcam|cameradfu|camera_dfu') } |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($candidate) { $cameraStoreFolder = $candidate.FullName }
    } catch {}

    # ── Step 4: PnP health gate ───────────────────────────────────────────────
    # If driver is confirmed healthy (ErrorCode=0), skip all reboot checks.
    # Stale PFRO entries and log timestamps are permanent records — the health
    # gate is the only reliable way to confirm restart already took effect.
    $healthResult = Test-CameraDriverHealthy -DriverVersion $camDriver.DriverVersion -InfName $camDriver.InfName

    if ($healthResult.Healthy) {
        $out_HealthCheckResult = "Healthy: $($healthResult.Reason)"
        $out_ActionRequired    = $false
        $out_Summary           = "Camera driver '$out_CameraDriverName' (v$out_CameraDriverVersion) is loaded and operational. No restart required."
        Write-NxtOutput
        exit 0
    }

    $out_HealthCheckResult = "Unhealthy-or-Inconclusive: $($healthResult.Reason)"

    # ── Step 5: PFRO — camera-attributed entries only ─────────────────────────
    $rebootCheck = Test-CameraRebootPendingRegistry `
                        -DriverVersion     $camDriver.DriverVersion `
                        -DriverInfName     $camDriver.InfName `
                        -DriverStoreFolder $cameraStoreFolder

    if ($rebootCheck.Pending) {
        $out_RebootPending = $true
        $out_RebootSource  = $rebootCheck.Source
    }

    # ── Step 6: Lenovo log cross-check ───────────────────────────────────────
    if (-not $out_RebootPending -and (Test-ThinInstallerCameraReboot)) {
        $out_RebootPending = $true
        $out_RebootSource  = "Lenovo-ThinInstaller-ExitCode3010"
    }
    if (-not $out_RebootPending -and (Test-SystemUpdateCameraReboot)) {
        $out_RebootPending = $true
        $out_RebootSource  = "Lenovo-SystemUpdate-RebootNeeded"
    }

    # ── Step 7: Set action required flag ─────────────────────────────────────
    if ($out_RebootPending) {
        $out_ActionRequired = $true
        $out_Summary = "Camera driver '$out_CameraDriverName' (v$out_CameraDriverVersion) updated on $out_CameraDriverDate. Restart pending via: $out_RebootSource. Camera may be non-functional until restarted."
    }
    else {
        $out_ActionRequired = $false
        $out_Summary = "Camera driver '$out_CameraDriverName' (v$out_CameraDriverVersion) is installed and no camera-attributed restart is pending."
    }

    # ── If no action needed — write outputs and exit cleanly ──────────────────
    if (-not $out_ActionRequired) {
        Write-NxtOutput
        exit 0
    }

    # ═════════════════════════════════════════════════════════════════════════
    # PHASE 2 — CAMPAIGN NOTIFICATION (only reached if ActionRequired = true)
    # ═════════════════════════════════════════════════════════════════════════

    # ── Step 8: Validate campaign parameter ───────────────────────────────────
    if ([string]::IsNullOrWhiteSpace($CampaignNqlId)) {
        # No campaign ID provided — still report the detection result, just skip campaign
        $out_CampaignStatus = "skipped"
        $out_Summary        = $out_Summary + " | Campaign skipped: CampaignNqlId parameter is empty."
        Write-NxtOutput
        exit 1
    }

    # ── Step 9: Run Engage campaign ───────────────────────────────────────────
    try {
        $campaignResponse  = [Nxt.CampaignAction]::RunCampaign($CampaignNqlId, $timeoutSecs)
        $out_CampaignStatus = [Nxt.CampaignAction]::GetResponseStatus($campaignResponse)

        # Capture which answer the user selected (question index 0 = first question)
        try {
            $answers = [Nxt.CampaignAction]::GetResponseAnswer($campaignResponse, 0)
            if ($answers -and $answers.Length -gt 0) { $out_UserResponse = $answers[0] }
        }
        catch { $out_UserResponse = "parse_error: $($_.Exception.Message)" }

        # ── Step 10: Auto-restart if user clicked "Restart Now" ───────────────
        if ($autoRestart -and $out_UserResponse -eq "Restart Now") {
            try {
                Start-Process -FilePath "shutdown.exe" `
                              -ArgumentList '/g /t 60 /c "Camera driver update requires a restart. Your apps will reopen after reboot."' `
                              -NoNewWindow -Wait
                $out_RestartInitiated = $true
            }
            catch {
                $out_Summary = $out_Summary + " | Auto-restart failed: $($_.Exception.Message)"
            }
        }

        if ($out_CampaignStatus -in @('connectionfailed', 'notificationfailed')) {
            $out_Summary = $out_Summary + " | Campaign not displayed. Status: $out_CampaignStatus"
        }
    }
    catch {
        $out_CampaignStatus = "script_error"
        $out_Summary        = $out_Summary + " | Campaign error: $($_.Exception.Message)"
    }

    Write-NxtOutput
    exit 1   # Exit 1 = action was required (campaign was fired)

}
catch {
    $out_Summary = "Script execution error: $($_.Exception.Message)"
    Write-NxtOutput
    exit 2
}
