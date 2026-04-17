#Requires -Version 5.1
<#
.SYNOPSIS
    Nexthink Remote Action — Camera Driver Reboot Pending Campaign Trigger.

.DESCRIPTION
    This script is the SECOND Remote Action in the camera reboot detection workflow.
    It is triggered conditionally — only on devices where the detection script
    (Lenovo-CameraDriver-RebootPending-Detection.ps1) has set NXT_ActionRequired=TRUE.

    Workflow:
      1. Loads the Nexthink Campaign Action DLL (nxtcampaignaction.dll).
      2. Runs the configured Engage campaign by Campaign NQL ID (recommended)
         or UID, displaying a user notification about the camera reboot.
      3. Waits for the user response (up to $CampaignTimeoutSeconds).
      4. Captures the user's answer and response status.
      5. Writes all outputs via the Nxt class for Nexthink data layer ingestion.
      6. If user chose "Restart Now" — initiates a graceful restart (optional,
         controlled by $EnableAutoRestart parameter).

    Campaign Response Statuses captured:
      fully       — User answered (accepted restart or dismissed)
      declined    — User declined to participate
      postponed   — User chose to be reminded later
      timeout     — Campaign timed out with no response
      connectionfailed / notificationfailed — Technical errors

    Output Variables (written via Nxt class for Nexthink data layer):
      CampaignStatus      — Response status string from campaign
      UserResponse        — The answer the user selected (e.g. "Restart Now")
      RestartInitiated    — Whether an auto-restart was triggered (bool)
      CampaignError       — Error message if something failed

.PARAMETER CampaignNqlId
    The NQL ID of the published Nexthink Engage campaign.
    Obtain from: Nexthink Infinity → Campaigns → right-click → Copy NQL ID
    Format example: "campaign:1234abcd-5678-efgh-ijkl-mnopqrstuvwx"
    This is passed as a Remote Action input parameter in the Nexthink console.

.PARAMETER CampaignTimeoutSeconds
    How long (in seconds) to wait for the user to respond before timing out.
    Default: 300 (5 minutes). Recommended range: 180–600.

.PARAMETER EnableAutoRestart
    If "true", the script will initiate a graceful restart (shutdown /g /t 60)
    when the user selects the "Restart Now" option in the campaign.
    Set to "false" to notify only without forcing a restart.
    Default: "false" (notify only — safer for enterprise deployments).

.NOTES
    Author      : Bharath (Enterprise Endpoint Management)
    Target      : Lenovo devices — Nexthink Infinity with Act + Engage
    Requires    : Nexthink Collector installed, nxtcampaignaction.dll present
                  Nexthink Act + Engage licenses
    Execution   : Run as SYSTEM (required to load Nexthink DLLs)
    Encoding    : UTF-8 with BOM (required for Nexthink Remote Actions)
    Exit Codes  :
        0 = Campaign delivered successfully (user responded or timed out)
        1 = Campaign could not be displayed (connection/notification failure)
        2 = Script execution error
#>

param(
    [string]$CampaignNqlId         = "",     # Set in Nexthink Remote Action console
    [string]$CampaignTimeoutSeconds = "300", # 5 minutes default
    [string]$EnableAutoRestart      = "false"
)

# ─────────────────────────────────────────────────────────────────────────────
# LOAD NEXTHINK ASSEMBLIES
# ─────────────────────────────────────────────────────────────────────────────
try {
    Add-Type -Path "$env:NEXTHINK\RemoteActions\nxtremoteactions.dll"   -ErrorAction Stop
    Add-Type -Path "$env:NEXTHINK\RemoteActions\nxtcampaignaction.dll"  -ErrorAction Stop
}
catch {
    # If DLLs are missing the Collector is not installed — exit cleanly
    Write-Output "ERROR: Could not load Nexthink assemblies. Is the Collector installed? $($_.Exception.Message)"
    exit 2
}

# ─────────────────────────────────────────────────────────────────────────────
# INITIALISE OUTPUT VARIABLES
# ─────────────────────────────────────────────────────────────────────────────
$outCampaignStatus   = "not_run"
$outUserResponse     = "N/A"
$outRestartInitiated = $false
$outCampaignError    = "None"

# ─────────────────────────────────────────────────────────────────────────────
# PARAMETER VALIDATION
# ─────────────────────────────────────────────────────────────────────────────
if ([string]::IsNullOrWhiteSpace($CampaignNqlId)) {
    $outCampaignError = "CampaignNqlId parameter is empty. Set it in the Remote Action configuration."
    [Nxt]::WriteOutputString("CampaignStatus",   $outCampaignStatus)
    [Nxt]::WriteOutputString("UserResponse",     $outUserResponse)
    [Nxt]::WriteOutputBool(  "RestartInitiated", $outRestartInitiated)
    [Nxt]::WriteOutputString("CampaignError",    $outCampaignError)
    exit 2
}

$timeoutSecs  = 300
$autoRestart  = $false
try { $timeoutSecs = [int]$CampaignTimeoutSeconds }   catch {}
try { $autoRestart = [System.Convert]::ToBoolean($EnableAutoRestart) } catch {}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN — RUN CAMPAIGN AND CAPTURE RESPONSE
# ─────────────────────────────────────────────────────────────────────────────
try {

    # Run campaign — waits for response or timeout
    # RunCampaign(NqlId, timeoutSeconds) — NQL ID is recommended over UID
    $campaignResponse = [Nxt.CampaignAction]::RunCampaign($CampaignNqlId, $timeoutSecs)

    # Get the high-level status string
    $outCampaignStatus = [Nxt.CampaignAction]::GetResponseStatus($campaignResponse)

    # ── Parse user answer ────────────────────────────────────────────────────
    # GetResponseAnswer returns the text of the answer the user clicked.
    # Index 0 = first (and only) question in our notification campaign.
    # Possible answers depend on what you configured in the Engage campaign builder:
    #   "Restart Now"    → user agreed to restart immediately
    #   "Remind Me Later"→ user wants to postpone
    #   "Dismiss"        → user acknowledged but chose not to restart now
    try {
        $answers = [Nxt.CampaignAction]::GetResponseAnswer($campaignResponse, 0)
        if ($answers -and $answers.Length -gt 0) {
            $outUserResponse = $answers[0]
        }
    }
    catch {
        # Answer parsing is best-effort; status is the primary signal
        $outUserResponse = "parse_error: $($_.Exception.Message)"
    }

    # ── Handle "Restart Now" answer ──────────────────────────────────────────
    # Only triggers if user explicitly clicked "Restart Now" AND EnableAutoRestart=true
    if ($autoRestart -and $outUserResponse -eq "Restart Now") {
        try {
            # Graceful restart: /g = restart apps after reboot, /t 60 = 60s warning
            # /c shows a reason message in the shutdown dialog
            Start-Process -FilePath "shutdown.exe" `
                          -ArgumentList '/g /t 60 /c "Your camera requires a system restart to function properly. Saving and restarting..."' `
                          -NoNewWindow -Wait
            $outRestartInitiated = $true
        }
        catch {
            $outCampaignError = "Restart initiation failed: $($_.Exception.Message)"
        }
    }

    # ── Flag non-delivery statuses ───────────────────────────────────────────
    if ($outCampaignStatus -in @('connectionfailed', 'notificationfailed')) {
        $outCampaignError = "Campaign could not be displayed to the user. Status: $outCampaignStatus"
    }

}
catch {
    $outCampaignStatus = "script_error"
    $outCampaignError  = $_.Exception.Message
}

# ─────────────────────────────────────────────────────────────────────────────
# WRITE OUTPUTS TO NEXTHINK DATA LAYER
# ─────────────────────────────────────────────────────────────────────────────
[Nxt]::WriteOutputString("CampaignStatus",   $outCampaignStatus)
[Nxt]::WriteOutputString("UserResponse",     $outUserResponse)
[Nxt]::WriteOutputBool(  "RestartInitiated", $outRestartInitiated)
[Nxt]::WriteOutputString("CampaignError",    $outCampaignError)

# ─────────────────────────────────────────────────────────────────────────────
# EXIT CODE
# ─────────────────────────────────────────────────────────────────────────────
if ($outCampaignStatus -in @('connectionfailed', 'notificationfailed', 'script_error')) {
    exit 1
}
exit 0




