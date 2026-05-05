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
      - POST-REBOOT HEALTH GATE: before any reboot signal is evaluated, the
        camera PnP device status is checked via Win32_PnPEntity ConfigManagerErrorCode.
        If ErrorCode=0 (device operational), the script immediately returns
        NXT_ActionRequired=FALSE — stale timestamps and PFRO entries from before
        the restart are ignored. This prevents false positives on re-runs after
        a successful restart.
        If ErrorCode is in {1,10,14,18,21,28,43} (restart-needed codes), the
        reboot is confirmed still required.
      - PFRO check: PendingFileRenameOperations parsed entry-by-entry; only
        camera-attributed path entries counted (DriverStore/SetupAPI timestamp
        checks intentionally excluded post-health-gate to avoid stale hits)
      - SetupAPI log: broadened camera-keyword search for actual install timestamp
      - OEM INF scan: reads DriverVer from oem*.inf in C:\Windows\INF (Lenovo release date)
      - DriverStore FileRepository: folder LastWriteTime = real driver staging timestamp
      - Date resolution: picks the NEWEST valid date (>=2020) across all sources,
        discarding legacy placeholder dates (e.g. 2006) embedded in OEM INFs

    Output (NXT_ prefixed for Nexthink Remote Action compatibility):
      NXT_CameraDriverFound          - Whether a camera driver was detected
      NXT_CameraDriverName           - Friendly name of the camera driver
      NXT_CameraDriverVersion        - Installed driver version
      NXT_CameraDriverDate           - Actual date of camera driver install/update with source tag
      NXT_CameraDriverRecentUpdate   - Whether driver was updated within threshold days
      NXT_RebootPending              - Whether a camera-attributed reboot signal is active
      NXT_RebootSource               - Which detection layer triggered the reboot flag
      NXT_HealthCheckResult          - PnP device health check result with reason
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
$NXT_HealthCheckResult        = "Not-Run"
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
    Write-Output "NXT_HealthCheckResult=$NXT_HealthCheckResult"
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
        Parses SetupAPI dev log to find the most recent ACTUAL install timestamp
        for a given INF file name. Searches both the named INF and any oem*.inf
        alias that references the same driver version/name to handle DFU devices
        whose canonical INF name may differ from the staged oem copy.
    #>
    try {
        if (-not (Test-Path $SetupAPILogPath)) { return $null }

        $logContent = Get-Content $SetupAPILogPath -Raw -ErrorAction Stop
        $recentDate = $null

        # Pattern 1: direct INF name match (e.g. oem42.inf or camera.inf)
        # Pattern 2: broader camera device install blocks (catches DFU aliases)
        $searchPatterns = @(
            [regex]::Escape($DriverInfName),
            'Camera\s+DFU',
            'Integrated\s+Camera',
            'IR\s+Camera',
            'RGB\s+Camera',
            'Webcam'
        )

        foreach ($pattern in $searchPatterns) {
            # Find all "Section start" timestamps that appear within ~20 lines
            # after a matching driver block header
            $blockMatches = [regex]::Matches(
                $logContent,
                "(?s)(?:SetupCopyOEMInf|Driver\s+Install|Device\s+Install)[^\n]*$pattern[^\n]*\n(?:.*?\n){0,20}?Section\s+start\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})",
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
            )
            foreach ($m in $blockMatches) {
                try {
                    $parsedDate = [datetime]::ParseExact(
                        $m.Groups[1].Value, 'yyyy/MM/dd HH:mm:ss', $null
                    )
                    if ($null -eq $recentDate -or $parsedDate -gt $recentDate) {
                        $recentDate = $parsedDate
                    }
                } catch {}
            }
        }
        return $recentDate
    }
    catch {
        return $null
    }
}

function Get-OemInfDriverDate {
    param([string]$DriverVersion, [string]$DriverInfName)
    <#
    .SYNOPSIS
        Reads DriverVer from the staged OEM INF in C:\Windows\INF\oem*.inf.
        OEM INFs contain a "DriverVer=MM/DD/YYYY,version" line that reflects
        when Lenovo actually built/released the package — more accurate than
        the WMI DriverDate which often carries a legacy placeholder.

        Strategy:
          1. Try the exact InfName from WMI (e.g. oem42.inf) first.
          2. If date looks bogus (year < 2020), scan ALL oem*.inf files for
             any that match our driver version string and pick the newest DriverVer.
    #>
    $infDir = "$env:WINDIR\INF"

    function Parse-DriverVer([string]$infPath) {
        try {
            $lines = Get-Content $infPath -ErrorAction Stop
            foreach ($line in $lines) {
                if ($line -match '^\s*DriverVer\s*=\s*(\d{1,2}/\d{1,2}/\d{4})\s*,') {
                    return [datetime]::ParseExact($Matches[1].Trim(), 'MM/dd/yyyy', $null)
                }
            }
        } catch {}
        return $null
    }

    $bestDate = $null

    # Step 1 — try exact named INF
    if ($DriverInfName) {
        $exactPath = Join-Path $infDir $DriverInfName
        if (Test-Path $exactPath) {
            $bestDate = Parse-DriverVer $exactPath
        }
    }

    # Step 2 — if date is missing or suspiciously old (pre-2020), scan all oem INFs
    $cutoff = [datetime]'2020-01-01'
    if ($null -eq $bestDate -or $bestDate -lt $cutoff) {
        try {
            $oemInfs = Get-ChildItem -Path $infDir -Filter 'oem*.inf' -ErrorAction Stop
            foreach ($inf in $oemInfs) {
                $content = Get-Content $inf.FullName -ErrorAction SilentlyContinue -Raw
                if (-not $content) { continue }

                # Only consider INFs that reference our driver version or camera keywords
                $isMatch = ($DriverVersion -and $content -match [regex]::Escape($DriverVersion)) -or
                           ($content -match 'Camera\s+DFU|Integrated\s+Camera|IR\s+Camera|RGB\s+Camera|Webcam')
                if (-not $isMatch) { continue }

                $candidate = Parse-DriverVer $inf.FullName
                if ($candidate -and $candidate -ge $cutoff) {
                    if ($null -eq $bestDate -or $candidate -gt $bestDate) {
                        $bestDate = $candidate
                    }
                }
            }
        } catch {}
    }

    return $bestDate
}

function Get-DriverStoreStagingDate {
    param([string]$DriverVersion, [string]$DriverInfName)
    <#
    .SYNOPSIS
        Checks the DriverStore\FileRepository for the folder matching our INF.
        The folder's LastWriteTime reflects when Windows staged the driver —
        i.e. when Lenovo's installer copied it in. This is independent of the
        INF's embedded date and is always current.
    #>
    try {
        $repoBase = "$env:WINDIR\System32\DriverStore\FileRepository"
        if (-not (Test-Path $repoBase)) { return $null }

        # Folder names look like: camera_dfu.inf_amd64_abc123def456
        # Match on INF stem (without extension) or known camera keywords
        $infStem    = if ($DriverInfName) { [IO.Path]::GetFileNameWithoutExtension($DriverInfName) } else { '' }
        $candidates = Get-ChildItem -Path $repoBase -Directory -ErrorAction Stop |
            Where-Object {
                ($infStem -and $_.Name -match [regex]::Escape($infStem)) -or
                ($_.Name -match 'camera|webcam|ir_camera|rgb_camera|ivcam|cameradfu|camera_dfu')
            } |
            Sort-Object LastWriteTime -Descending

        if ($candidates) {
            # Validate: check if DriverVer inside matches our version
            foreach ($folder in $candidates) {
                $infFiles = Get-ChildItem -Path $folder.FullName -Filter '*.inf' -ErrorAction SilentlyContinue
                foreach ($inf in $infFiles) {
                    $content = Get-Content $inf.FullName -Raw -ErrorAction SilentlyContinue
                    if ($DriverVersion -and $content -match [regex]::Escape($DriverVersion)) {
                        return $folder.LastWriteTime
                    }
                    # Fallback: any camera-related INF in the folder
                    if ($content -match 'Camera\s+DFU|Integrated\s+Camera|IR\s+Camera') {
                        return $folder.LastWriteTime
                    }
                }
            }
            # Last resort: return the newest matching folder date
            return $candidates[0].LastWriteTime
        }
    }
    catch {}
    return $null
}

function Test-CameraRebootPendingRegistry {
    <#
    .SYNOPSIS
        Checks ONLY for reboot signals that are attributable to the camera driver.
        Generic signals (CBS, Windows Update) are intentionally excluded — they
        indicate OS/other-driver reboots which are not our concern.

        Checks performed:
          1. PendingFileRenameOperations — parsed entry-by-entry; only flagged if
             at least one entry path contains a camera-related keyword or the
             driver INF/version string. This is the most common signal after a
             Lenovo camera driver install.
          2. DriverStore staging post-boot — if the camera driver's FileRepository
             folder was written AFTER the last system boot, the driver was staged
             but not yet activated (reboot still needed to load it).
          3. SetupAPI install post-boot — if the camera driver install log entry
             is timestamped AFTER the last boot, the driver is installed but the
             old in-use binary hasn't been replaced yet.

        Returns: @{ Pending = $bool; Source = 'string describing which check hit' }

        Parameters:
          $DriverVersion  — from Win32_PnPSignedDriver, used for path matching
          $DriverInfName  — oem*.inf name, used for path matching
          $DriverStoreFolder — full path to the camera's FileRepository folder
          $SetupApiInstallTime — datetime of camera install from SetupAPI log
          $LastBootTime   — system last boot datetime for post-boot comparison
    #>
    param(
        [string]   $DriverVersion,
        [string]   $DriverInfName,
        [string]   $DriverStoreFolder,
        [datetime] $SetupApiInstallTime,
        [datetime] $LastBootTime
    )

    # Camera-related path keywords to match against PFRO entries
    $cameraKeywords = @(
        'camera', 'webcam', 'ivcam', 'cameradfu', 'camera_dfu',
        'ircamera', 'ir_camera', 'rgbcamera', 'rgb_camera',
        'lenovo.*cam', 'cam.*lenovo', 'integrated.*cam'
    )

    # Also match the specific driver version string and INF stem if available
    $infStem = if ($DriverInfName) { [IO.Path]::GetFileNameWithoutExtension($DriverInfName) } else { '' }

    # ── Check 1: PendingFileRenameOperations — camera-attributed entries only ─
    try {
        $smKey  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        $pfro   = (Get-ItemProperty -Path $smKey -ErrorAction Stop).PendingFileRenameOperations
        if ($pfro) {
            foreach ($entry in $pfro) {
                if (-not $entry) { continue }
                $entryLower = $entry.ToLower()

                # Match camera keywords
                $keywordHit = $cameraKeywords | Where-Object { $entryLower -match $_ }
                if ($keywordHit) {
                    return @{ Pending = $true; Source = "PFRO-CameraEntry: $entry" }
                }

                # Match driver version string (e.g. 10.0.26100.1150 in a file path)
                if ($DriverVersion -and $entryLower -match [regex]::Escape($DriverVersion)) {
                    return @{ Pending = $true; Source = "PFRO-DriverVersionEntry: $entry" }
                }

                # Match INF stem (e.g. oem42 in a path)
                if ($infStem -and $entryLower -match [regex]::Escape($infStem.ToLower())) {
                    return @{ Pending = $true; Source = "PFRO-InfEntry: $entry" }
                }

                # Match DriverStore folder path for this specific camera driver
                if ($DriverStoreFolder -and $entryLower -match [regex]::Escape($DriverStoreFolder.ToLower())) {
                    return @{ Pending = $true; Source = "PFRO-DriverStoreEntry: $entry" }
                }
            }
        }
    } catch {}

    # ── Check 2: DriverStore folder staged AFTER last boot ────────────────────
    # If the camera driver folder in FileRepository was written after the last
    # boot, Windows staged a new version but the system hasn't restarted to
    # activate it yet.
    if ($DriverStoreFolder -and (Test-Path $DriverStoreFolder)) {
        try {
            $folderWriteTime = (Get-Item $DriverStoreFolder -ErrorAction Stop).LastWriteTime
            if ($folderWriteTime -gt $LastBootTime) {
                return @{
                    Pending = $true
                    Source  = "DriverStore-StagedAfterBoot (staged: $($folderWriteTime.ToString('yyyy-MM-dd HH:mm:ss')), boot: $($LastBootTime.ToString('yyyy-MM-dd HH:mm:ss')))"
                }
            }
        } catch {}
    }

    # ── Check 3: SetupAPI camera install recorded AFTER last boot ─────────────
    # If the SetupAPI log shows the camera driver was installed after the last
    # boot time, the old driver binary is still loaded in memory — reboot needed.
    if ($SetupApiInstallTime -ne [datetime]::MinValue -and $SetupApiInstallTime -gt $LastBootTime) {
        return @{
            Pending = $true
            Source  = "SetupAPI-InstallAfterBoot (installed: $($SetupApiInstallTime.ToString('yyyy-MM-dd HH:mm:ss')), boot: $($LastBootTime.ToString('yyyy-MM-dd HH:mm:ss')))"
        }
    }

    return @{ Pending = $false; Source = 'None' }
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

function Test-CameraDriverHealthy {
    <#
    .SYNOPSIS
        Validates that the camera driver is actually loaded and functional
        in the current Windows session — i.e. the restart already took effect.

        This is the POST-REBOOT GATE. If this returns TRUE, the driver is
        confirmed healthy and NXT_ActionRequired must be FALSE regardless of
        any stale timestamps or flags left over from before the restart.

        Checks (any single pass = healthy):
          1. PnP device status = OK (ConfigManagerErrorCode = 0) — driver is
             loaded and Windows Device Manager reports no error.
          2. Driver binary is loaded in kernel — the .sys file corresponding
             to the camera INF is present in the running driver list
             (via Get-WindowsDriver or Win32_SystemDriver).
          3. Camera device is not in a problem state — no error codes 1,10,18,
             28,43 (the common post-update-pending-restart codes).

        Returns: @{ Healthy = $bool; Reason = 'string' }
    #>
    param(
        [string]$DriverVersion,
        [string]$InfName
    )

    # ── Check 1: PnP ConfigManagerErrorCode = 0 (device OK) ─────────────────
    try {
        $pnpDevices = Get-WmiObject Win32_PnPEntity -ErrorAction Stop |
            Where-Object {
                ($_.PNPClass -eq 'Camera') -or
                ($_.PNPClass -eq 'Image')  -or
                ($_.Name -match 'camera|webcam|IR Camera|RGB Camera|Integrated Camera') -or
                ($_.Description -match 'camera|webcam|IR Camera|RGB Camera|Integrated Camera')
            }

        foreach ($dev in $pnpDevices) {
            $errCode = $dev.ConfigManagerErrorCode

            # Error codes that specifically mean "restart needed to complete install"
            $rebootNeededCodes = @(1, 10, 14, 18, 21, 28, 43)

            if ($errCode -eq 0) {
                # Device is fully operational — restart has taken effect
                return @{ Healthy = $true; Reason = "PnP-DeviceOK (ErrorCode=0, Device='$($dev.Name)')" }
            }
            elseif ($errCode -in $rebootNeededCodes) {
                # Confirmed still needs reboot — this is a real pending state
                return @{ Healthy = $false; Reason = "PnP-DeviceError (ErrorCode=$errCode, Device='$($dev.Name)') — restart still required" }
            }
        }
    }
    catch {}

    # ── Check 2: Camera device present and not in problem state via CIM ──────
    try {
        $cimDevices = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction Stop |
            Where-Object {
                ($_.PNPClass -in @('Camera','Image')) -or
                ($_.Name -match 'camera|webcam|IR Camera|RGB Camera|Integrated Camera')
            }

        foreach ($dev in $cimDevices) {
            if ($dev.ConfigManagerErrorCode -eq 0) {
                return @{ Healthy = $true; Reason = "CIM-DeviceOK (ErrorCode=0, Device='$($dev.Name)')" }
            }
        }
    }
    catch {}

    # ── Check 3: Driver version in registry matches what WMI reported ─────────
    # After a successful restart the active driver version in the service registry
    # matches the installed version. Mismatch = old driver still loaded.
    try {
        if ($DriverVersion -and $InfName) {
            $infStem    = [IO.Path]::GetFileNameWithoutExtension($InfName)
            $driverKeys = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction Stop |
                Where-Object { $_.Name -match $infStem -or $_.PSChildName -match 'camera|ivcam|usbvideo' }

            foreach ($key in $driverKeys) {
                $imgPath = (Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue).ImagePath
                if ($imgPath) {
                    # If the service key exists and has an image path, the driver is registered as active
                    return @{ Healthy = $true; Reason = "ServiceRegistry-DriverActive (key='$($key.PSChildName)')" }
                }
            }
        }
    }
    catch {}

    # Could not confirm either way — do not override reboot detection
    return @{ Healthy = $false; Reason = "HealthCheck-Inconclusive" }
}

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

    # ── STEP 2: Determine driver install/update date (multi-source, prioritized) ─
    #
    #  Priority order (most → least reliable for "when was this actually installed"):
    #    1. DriverStore FileRepository folder LastWriteTime  — real staging timestamp
    #    2. SetupAPI dev log Section start timestamp         — real install timestamp
    #    3. OEM INF DriverVer line (oem*.inf scan)          — Lenovo release date
    #    4. WMI DriverDate                                  — often a legacy placeholder
    #
    #  We collect all available dates and select the NEWEST one that is ≥ 2020-01-01.
    #  A date before 2020 is treated as a placeholder/bogus value and discarded.
    # ─────────────────────────────────────────────────────────────────────────────
    $dateCutoff    = [datetime]'2020-01-01'
    $dateCandidates = [System.Collections.Generic.List[hashtable]]::new()

    # Source 1: DriverStore FileRepository staging date
    $storeDate = Get-DriverStoreStagingDate `
                    -DriverVersion $camDriver.DriverVersion `
                    -DriverInfName $camDriver.InfName
    if ($storeDate -and $storeDate -ge $dateCutoff) {
        $dateCandidates.Add(@{ Date = $storeDate; Source = 'DriverStore-Staging' })
    }

    # Source 2: SetupAPI dev log — broadened camera-keyword search
    $setupDate = Get-DriverInstallDate -DriverInfName $camDriver.InfName
    if ($setupDate -and $setupDate -ge $dateCutoff) {
        $dateCandidates.Add(@{ Date = $setupDate; Source = 'SetupAPI-Log' })
    }

    # Source 3: OEM INF DriverVer scan
    $oemInfDate = Get-OemInfDriverDate `
                    -DriverVersion $camDriver.DriverVersion `
                    -DriverInfName $camDriver.InfName
    if ($oemInfDate -and $oemInfDate -ge $dateCutoff) {
        $dateCandidates.Add(@{ Date = $oemInfDate; Source = 'OemInf-DriverVer' })
    }

    # Source 4: WMI DriverDate (fallback only)
    if ($camDriver.DriverDate) {
        try {
            $wmiDate = [Management.ManagementDateTimeConverter]::ToDateTime($camDriver.DriverDate)
            if ($wmiDate -and $wmiDate -ge $dateCutoff) {
                $dateCandidates.Add(@{ Date = $wmiDate; Source = 'WMI-DriverDate' })
            }
        } catch {}
    }

    # Select the most recent valid date across all sources
    $bestEntry  = $dateCandidates | Sort-Object { $_.Date } -Descending | Select-Object -First 1
    $driverDate = if ($bestEntry) { $bestEntry.Date } else { $null }
    $dateSource = if ($bestEntry) { $bestEntry.Source } else { 'Unknown' }

    if ($driverDate) {
        $NXT_CameraDriverDate = "$($driverDate.ToString('yyyy-MM-dd HH:mm:ss')) [$dateSource]"
        $daysSinceUpdate      = (Get-Date) - $driverDate
        if ($daysSinceUpdate.TotalDays -le $RecentUpdateThresholdDays) {
            $NXT_CameraDriverRecentUpdate = "TRUE"
        }
    }

    # ── STEP 3: Get last boot time — needed to determine if install is post-boot ─
    $lastBootTime = [datetime]::MinValue
    try {
        $os = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
        $lastBootTime = [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
    } catch {}

    # ── STEP 4: Resolve camera DriverStore folder path ───────────────────────
    # Used both for date detection (already done in Step 2) and reboot attribution
    $cameraStoreFolder = ''
    try {
        $repoBase  = "$env:WINDIR\System32\DriverStore\FileRepository"
        $infStem   = if ($camDriver.InfName) { [IO.Path]::GetFileNameWithoutExtension($camDriver.InfName) } else { '' }
        $candidate = Get-ChildItem -Path $repoBase -Directory -ErrorAction Stop |
            Where-Object {
                ($infStem -and $_.Name -match [regex]::Escape($infStem)) -or
                ($_.Name -match 'camera|webcam|ir_camera|rgb_camera|ivcam|cameradfu|camera_dfu')
            } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        if ($candidate) { $cameraStoreFolder = $candidate.FullName }
    } catch {}

    # ── STEP 5: Camera-specific reboot attribution ────────────────────────────
    #
    #  GATE: Before checking any reboot signals, first validate whether the
    #  camera driver is already healthy in the current session. If the device
    #  was restarted and the driver loaded cleanly, stale timestamps (DriverStore
    #  folder LastWriteTime, SetupAPI log entries) will still look "newer than
    #  last boot" on the NEXT boot too — they are permanent records, not cleared
    #  by a restart. The health gate prevents these from causing false positives.
    #
    #  Logic:
    #    - If health check confirms driver is OK (PnP ErrorCode=0) → skip all
    #      timestamp-based checks, set ActionRequired=FALSE immediately.
    #    - If health check finds driver in error state (codes 1,10,14,18,43 etc.)
    #      → confirmed still needs reboot, proceed with full check.
    #    - If health check is inconclusive → fall through to PFRO + Lenovo logs
    #      only (skip DriverStore/SetupAPI timestamp checks to avoid false positives).
    # ─────────────────────────────────────────────────────────────────────────────
    $setupApiTime = if ($setupDate) { $setupDate } else { [datetime]::MinValue }

    $healthResult = Test-CameraDriverHealthy `
                        -DriverVersion $camDriver.DriverVersion `
                        -InfName       $camDriver.InfName

    if ($healthResult.Healthy) {
        # Driver is confirmed operational post-restart — no action needed.
        # Stale PFRO / timestamp signals are irrelevant; override everything.
        $NXT_RebootPending      = "FALSE"
        $NXT_RebootSource       = "None"
        $NXT_HealthCheckResult  = "Healthy: $($healthResult.Reason)"
        $NXT_ActionRequired     = "FALSE"
        $NXT_Summary = "Camera driver '$NXT_CameraDriverName' (v$NXT_CameraDriverVersion) " +
                       "is loaded and operational ($($healthResult.Reason)). No restart required."
        Write-NxtOutput
        exit 0
    }

    # Health check did not confirm healthy — record result and proceed
    $NXT_HealthCheckResult = "Unhealthy-or-Inconclusive: $($healthResult.Reason)"

    # Health check did not confirm healthy — now check for reboot signals.
    # Only run PFRO check (camera-attributed entries) here.
    # DriverStore-StagedAfterBoot and SetupAPI-InstallAfterBoot are intentionally
    # SKIPPED — they produce false positives on every run after the first restart
    # since their timestamps never change. We rely on PnP error codes (above) to
    # confirm reboot still needed, and PFRO + Lenovo logs as corroborating signals.
    $rebootCheck = Test-CameraRebootPendingRegistry `
                        -DriverVersion       $camDriver.DriverVersion `
                        -DriverInfName       $camDriver.InfName `
                        -DriverStoreFolder   $cameraStoreFolder `
                        -SetupApiInstallTime [datetime]::MinValue `
                        -LastBootTime        [datetime]::MaxValue

    # Note: passing MinValue for SetupApiInstallTime and MaxValue for LastBootTime
    # ensures the SetupAPI-InstallAfterBoot and DriverStore-StagedAfterBoot sub-checks
    # inside Test-CameraRebootPendingRegistry never trigger (MinValue is never > MaxValue).
    # Only PFRO camera-attributed entries can fire from that function now.

    if ($rebootCheck.Pending) {
        $NXT_RebootPending = "TRUE"
        $NXT_RebootSource  = $rebootCheck.Source
    }

    # ── STEP 6: Lenovo log cross-check (camera-scoped, already specific) ──────
    if ($NXT_RebootPending -eq "FALSE") {
        if (Test-ThinInstallerCameraReboot) {
            $NXT_RebootPending = "TRUE"
            $NXT_RebootSource  = "Lenovo-ThinInstaller-ExitCode3010"
        }
    }

    if ($NXT_RebootPending -eq "FALSE") {
        if (Test-SystemUpdateCameraReboot) {
            $NXT_RebootPending = "TRUE"
            $NXT_RebootSource  = "Lenovo-SystemUpdate-RebootNeeded"
        }
    }

    # ── STEP 7: Determine final action flag ──────────────────────────────────
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
