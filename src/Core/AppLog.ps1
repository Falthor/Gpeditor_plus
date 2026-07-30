<#
    Persistent application log: a single log file that keeps growing across
    launches (not one file per session). Every setting change (parameter
    name, key/registry path, old value, new value) and every project
    create/import/export/save is appended here with a timestamp, one
    field per line for readability.
#>

$script:LogFilePath = $null

function Initialize-GpEditLog {
    param([Parameter(Mandatory)][string]$LogDir)

    if (-not (Test-Path -LiteralPath $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    $script:LogFilePath = Join-Path $LogDir 'gpedit.log'
    if (-not (Test-Path -LiteralPath $script:LogFilePath)) {
        New-Item -ItemType File -Path $script:LogFilePath -Force | Out-Null
    }
    return $script:LogFilePath
}

function Write-GpEditLogLine {
    param([Parameter(Mandatory)][string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -LiteralPath $script:LogFilePath -Value "[$timestamp] $Message" -Encoding UTF8
}

function Write-GpEditLogDetailLine {
    param([Parameter(Mandatory)][string]$Message)
    Add-Content -LiteralPath $script:LogFilePath -Value "    $Message" -Encoding UTF8
}

function Write-GpEditSettingChangeLog {
    param(
        [Parameter(Mandatory)][string]$ParameterName,
        [string]$Key,
        $OldValue,
        $NewValue
    )
    $hasOld = -not [string]::IsNullOrEmpty("$OldValue")
    $hasNew = -not [string]::IsNullOrEmpty("$NewValue")
    $action = if ($hasNew -and -not $hasOld) { 'SETTING ADDED' }
              elseif ($hasOld -and -not $hasNew) { 'SETTING REMOVED' }
              else { 'SETTING CHANGED' }

    Write-GpEditLogLine -Message $action
    Write-GpEditLogDetailLine -Message "Name: $ParameterName"
    Write-GpEditLogDetailLine -Message "Registry: $Key"
    if ($hasOld) { Write-GpEditLogDetailLine -Message "Old value: $OldValue" }
    if ($hasNew) { Write-GpEditLogDetailLine -Message "New value: $NewValue" }
}

function Write-GpEditImportStartLog {
    param(
        [Parameter(Mandatory)][string]$ProjectName
    )
    Write-GpEditLogLine -Message ('*' * 73)
    Write-GpEditLogLine -Message 'Starting PROJECT IMPORT'
    Write-GpEditLogDetailLine -Message "Name: $ProjectName"
}

function Write-GpEditProjectLog {
    param(
        [Parameter(Mandatory)][ValidateSet('Created', 'Imported', 'Exported', 'Saved')][string]$Action,
        [Parameter(Mandatory)][string]$ProjectName,
        [string]$Location
    )
    Write-GpEditLogLine -Message "PROJECT $($Action.ToUpper())"
    Write-GpEditLogDetailLine -Message "Name: $ProjectName"
    if ($Location) { Write-GpEditLogDetailLine -Message "Location: $Location" }
}

function Open-GpEditLogFile {
    if ($script:LogFilePath -and (Test-Path -LiteralPath $script:LogFilePath)) {
        Start-Process -FilePath $script:LogFilePath
    }
}

# Separate error log: every terminating error caught by the script-level
# trap in GpEdit.ps1 is appended here, independent from the activity log
# above. Hardcoded default path (rather than $AppSettings.paths.logDir) so
# it still works if error-triggering code runs before/without AppSettings.
$script:ErrorLogFilePath = $null

function Initialize-GpEditErrorLog {
    param([string]$LogDir = 'C:\Windows\Logs\Gpeditor_plus')

    if (-not (Test-Path -LiteralPath $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    $script:ErrorLogFilePath = Join-Path $LogDir 'Gpeditor_Error.log'
    if (-not (Test-Path -LiteralPath $script:ErrorLogFilePath)) {
        New-Item -ItemType File -Path $script:ErrorLogFilePath -Force | Out-Null
    }
    return $script:ErrorLogFilePath
}

function Write-GpEditErrorLog {
    param([Parameter(Mandatory)]$ErrorRecord)

    if (-not $script:ErrorLogFilePath) { Initialize-GpEditErrorLog | Out-Null }
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $inv = $ErrorRecord.InvocationInfo
    $stack = if ($ErrorRecord.ScriptStackTrace) { ($ErrorRecord.ScriptStackTrace -replace '\r?\n', ' | ') } else { '(none)' }
    $lines = @(
        "[$timestamp] ERROR: $($ErrorRecord.Exception.Message)"
        "    Category: $($ErrorRecord.CategoryInfo.Category) ($($ErrorRecord.FullyQualifiedErrorId))"
        "    At: $($inv.ScriptName):$($inv.ScriptLineNumber) char:$($inv.OffsetInLine)"
        "    Line: $($inv.Line.Trim())"
        "    Stack: $stack"
    )
    Add-Content -LiteralPath $script:ErrorLogFilePath -Value $lines -Encoding UTF8
}
