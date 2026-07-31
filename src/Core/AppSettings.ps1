<#
    Configurable default locations (File > Options), "Editor Mode" toggle and
    default File > Import mode, persisted in
    %LocalAppData%\Gpeditor_plus\settings.json. Of the 7 paths from
    Get-DefaultAppPaths, tempDir and indexDir are fixed (not exposed in the
    Options UI); the other 5, the editorMode bool and defaultImportMode
    (Classic/Standard/Advanced, see Options > Others > Import) are
    user-editable.

    Each "paths" key replaces a historically repo-relative default (see
    GpEdit.ps1) with a standard Windows location. No migration of old repo
    files: on first run, folders are created empty, except auditFilesDir
    which is seeded from src\DefaultData\*.audit (see Initialize-AppSettingsFirstRun).
#>

Set-StrictMode -Version Latest

function Get-AppSettingsPath {
    Join-Path $env:LOCALAPPDATA 'Gpeditor_plus\settings.json'
}

function Get-DefaultAppPaths {
    @{
        logDir          = 'C:\Windows\Logs\Gpeditor_plus\'
        tempDir         = (Join-Path $env:LOCALAPPDATA 'Gpeditor_plus\')
        backupRoot      = 'C:\ProgramData\Gpeditor_plus\Backup\'
        importExportDir = 'C:\ProgramData\Gpeditor_plus\export\'
        auditFilesDir   = 'C:\ProgramData\Gpeditor_plus\audit\'
        indexDir        = (Join-Path $env:LOCALAPPDATA 'Gpeditor_plus\Index\')
        projectsDir     = 'C:\ProgramData\Gpeditor_plus\project\'
    }
}

function Get-AppSettings {
    <#
        Tolerant load: missing/unreadable file falls back fully to defaults
        (same spirit as Import-CisIndex). Merges key-by-key with
        Get-DefaultAppPaths to survive a partial or older-schema file
        without breaking under Set-StrictMode -Version Latest.
    #>
    $defaults = Get-DefaultAppPaths
    $settings = [pscustomobject]@{
        paths             = [pscustomobject]$defaults
        editorMode        = $true
        defaultImportMode = 'Classic'
    }

    $path = Get-AppSettingsPath
    if (-not (Test-Path -LiteralPath $path)) { return $settings }

    try {
        $loaded = Get-Content -Raw -Encoding UTF8 -LiteralPath $path | ConvertFrom-Json
    }
    catch {
        Write-Warning "Settings unreadable ($path): $($_.Exception.Message) - using defaults."
        return $settings
    }

    if ($loaded.PSObject.Properties['paths']) {
        foreach ($key in $defaults.Keys) {
            if ($loaded.paths.PSObject.Properties[$key] -and $loaded.paths.$key) {
                $settings.paths.$key = $loaded.paths.$key
            }
        }
    }
    if ($loaded.PSObject.Properties['editorMode']) {
        $settings.editorMode = [bool]$loaded.editorMode
    }
    if ($loaded.PSObject.Properties['defaultImportMode'] -and $loaded.defaultImportMode) {
        $settings.defaultImportMode = $loaded.defaultImportMode
    }

    return $settings
}

function Save-AppSettings {
    param([Parameter(Mandatory)]$Settings)

    $path = Get-AppSettingsPath
    $dir = Split-Path -Parent $path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $Settings | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path -Encoding UTF8
}

function Set-AppSettingPath {
    <# Updates a single path (Key from Get-DefaultAppPaths) and saves immediately. #>
    param(
        [Parameter(Mandatory)]$Settings,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Value
    )
    $Settings.paths.$Key = $Value
    Save-AppSettings -Settings $Settings
}

function Initialize-AppSettingsFirstRun {
    <#
        Call once at startup, right after Get-AppSettings. If settings.json
        didn't exist before this call (first run), creates the default
        folders and seeds auditFilesDir from the .audit files bundled in
        src\DefaultData (23 CIS benchmarks, unused elsewhere). Never fires
        again once settings.json exists: user deletions in the Audit folder
        stay permanent.
    #>
    param(
        [Parameter(Mandatory)]$Settings,
        [Parameter(Mandatory)][string]$ScriptRoot
    )

    $isFirstRun = -not (Test-Path -LiteralPath (Get-AppSettingsPath))
    if (-not $isFirstRun) { return }

    foreach ($prop in $Settings.paths.PSObject.Properties) {
        if (-not (Test-Path -LiteralPath $prop.Value)) { New-Item -ItemType Directory -Path $prop.Value -Force | Out-Null }
    }

    $defaultDataDir = Join-Path $ScriptRoot 'DefaultData'
    if (Test-Path -LiteralPath $defaultDataDir) {
        Copy-Item -Path (Join-Path $defaultDataDir '*.audit') -Destination $Settings.paths.auditFilesDir -Force
    }

    Save-AppSettings -Settings $Settings
}
