<#
    Persistent application log: a single log file that keeps growing across
    launches (not one file per session). Every setting change (parameter
    name, key/registry path, old value, new value) and every project
    create/import/export is appended here with a timestamp.
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

function Format-GpEditLogValue {
    param($Value)
    if ($null -eq $Value -or $Value -eq '') { return '(not defined)' }
    return "$Value"
}

function Write-GpEditSettingChangeLog {
    param(
        [Parameter(Mandatory)][string]$ParameterName,
        [string]$Key,
        $OldValue,
        $NewValue
    )
    $oldText = Format-GpEditLogValue -Value $OldValue
    $newText = Format-GpEditLogValue -Value $NewValue
    Write-GpEditLogLine -Message "SETTING CHANGE | Parameter: $ParameterName | Key: $Key | Old value: $oldText | New value: $newText"
}

function Write-GpEditImportStartLog {
    param(
        [Parameter(Mandatory)][string]$ProjectName
    )
    Write-GpEditLogLine -Message ('*' * 73)
    Write-GpEditLogLine -Message "Starting PROJECT IMPORT | Name: $ProjectName"
}

function Write-GpEditProjectLog {
    param(
        [Parameter(Mandatory)][ValidateSet('Created', 'Imported', 'Exported')][string]$Action,
        [Parameter(Mandatory)][string]$ProjectName
    )
    Write-GpEditLogLine -Message "PROJECT $($Action.ToUpper()) | Name: $ProjectName"
}

function Open-GpEditLogFile {
    if ($script:LogFilePath -and (Test-Path -LiteralPath $script:LogFilePath)) {
        Start-Process -FilePath $script:LogFilePath
    }
}
