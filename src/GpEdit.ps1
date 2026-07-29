<#
    Main entry point: WPF interface (category tree on the left, settings
    list on the right), backed by the ADMX and Security indexes, with
    current state read from registry.pol / GptTmpl.inf.

    Language: English (en-US) only - no language selector.

    Cache freshness: a fingerprint of the PolicyDefinitions folder is
    computed on every launch (PolicyDefinitionsFingerprint.ps1). If it does
    not match the one stored in the existing JSON index, ADMX/ADML parsing
    is redone automatically. The Audit files folder (CIS benchmarks) is
    covered the same way (AuditFilesFingerprint.ps1) so that Build-CisIndex.ps1
    reruns automatically whenever its content changed, whether from the
    Options window or a direct edit of the folder.
#>
param(
    [string]$MachinePolPath    = 'C:\Windows\System32\GroupPolicy\Machine\registry.pol',
    [string]$UserPolPath       = 'C:\Windows\System32\GroupPolicy\User\registry.pol',
    [string]$SecEditInfPath    = (Join-Path $env:LOCALAPPDATA 'Gpeditor_plus\secedit.inf'),
    [string]$GptIniPath        = 'C:\Windows\System32\GroupPolicy\GPT.ini',
    [string]$AuditCsvPath      = 'C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv',
    [string]$PolicyDefinitionsPath = (Join-Path $env:WinDir 'PolicyDefinitions'),
    [string]$DataPath          = (Join-Path $PSScriptRoot '..\data'),
    [string]$BackupRoot        = (Join-Path $PSScriptRoot '..\Backups')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml, System.Windows.Forms | Out-Null

. (Join-Path $PSScriptRoot 'Core\AppLog.ps1')
. (Join-Path $PSScriptRoot 'Core\AppSettings.ps1')
. (Join-Path $PSScriptRoot 'Parsers\PolFile.ps1')
. (Join-Path $PSScriptRoot 'Parsers\GptIniFile.ps1')
. (Join-Path $PSScriptRoot 'Parsers\GptTmplFile.ps1')
. (Join-Path $PSScriptRoot 'Catalogs\SecurityCatalog.ps1')
. (Join-Path $PSScriptRoot 'Policy\PolicyState.ps1')
. (Join-Path $PSScriptRoot 'UI\EditDialogs.ps1')
. (Join-Path $PSScriptRoot 'UI\SelectPrincipalsDialog.ps1')
. (Join-Path $PSScriptRoot 'UI\OptionsDialog.ps1')
. (Join-Path $PSScriptRoot 'UI\UiStrings.ps1')
. (Join-Path $PSScriptRoot 'Indexers\PolicyDefinitionsFingerprint.ps1')
. (Join-Path $PSScriptRoot 'Indexers\AuditFilesFingerprint.ps1')
. (Join-Path $PSScriptRoot 'Policy\PolicyWriter.ps1')
. (Join-Path $PSScriptRoot 'Policy\ChangeApplier.ps1')
. (Join-Path $PSScriptRoot 'Parsers\AuditCsvFile.ps1')
. (Join-Path $PSScriptRoot 'Catalogs\AdvancedAuditCatalog.ps1')
. (Join-Path $PSScriptRoot 'Catalogs\CisCatalog.ps1')
. (Join-Path $PSScriptRoot 'Parsers\ChangelogFile.ps1')
. (Join-Path $PSScriptRoot 'UI\AppDialogs.ps1')
. (Join-Path $PSScriptRoot 'Core\ImportGpoProjectFiles.ps1')

# --- Mandatory elevation on launch --------------------------------------
# Test-IsRunningAsAdministrator alone covers both UAC-enabled (not elevated)
# and UAC-disabled (non-admin session) cases; only the shown message differs.
if (-not (Test-IsRunningAsAdministrator)) {
    $startupUi = Get-UiStrings
    $startupMessage = if (Test-IsUacEnabled) { $startupUi.LaunchNotElevatedMessage } else { $startupUi.LaunchNotAdminAccountMessage }
    [System.Windows.MessageBox]::Show($startupMessage, $startupUi.LaunchBlockedTitle, 'OK', 'Error') | Out-Null
    return
}

# File > Options: default locations + Editor Mode, persisted in
# %LocalAppData%\Gpeditor_plus\settings.json (see AppSettings.ps1). First
# launch creates default folders and seeds Audit from src\DefaultData\*.audit.
$script:AppSettings = Get-AppSettings
Initialize-AppSettingsFirstRun -Settings $script:AppSettings -ScriptRoot $PSScriptRoot
$script:CatalogEditingEnabled = $script:AppSettings.editorMode
$BackupRoot = $script:AppSettings.paths.backupRoot
$SecEditInfPath = Join-Path $script:AppSettings.paths.tempDir 'secedit.inf'

# True once an Account Policies/Local Policies setting changed this session -
# gates whether Invoke-SecEditInfApply (real secedit /import+/configure) runs
# on window close, avoiding an admin/secedit round trip for read-only sessions.
$script:SecEditInfDirty = $false

# True once a setting changed while a GPO project is active but not yet
# pushed by "Save now" - drives Update-SaveNowButtonVisibility and the
# close-time unsaved-changes warning. Reset on new/opened project and after
# a successful push in Save-GpoProjectChanges.
$script:ProjectDirty = $false

# True once a Security Options setting changed outside any GPO project -
# lets Export-GpoProjectFiles apply secedit immediately at export time
# rather than waiting for window close. Never reset once set; the
# close-time apply (gated on SecEditInfDirty) still runs regardless
# (deliberate redundancy).
$script:SecurityOptionsDirty = $false

# Advanced menu (GPO projects): $ActiveProject is $null when no off-machine
# project is active, else @{ Dir = ...; Name = ... }, set by
# Set-ActiveGpoProject. DefaultGpPath points at the bundled read-only
# Default.pol/Default.csv/Default.cfg template; not user-configurable so it
# can't be pointed at a missing/tampered folder.
$script:ActiveProject = $null
$script:DefaultGpPath = Join-Path $PSScriptRoot 'DefaultData\int_default_grouppolicy'

# Persistent log file (see AppLog.ps1) - one file, appended across launches.
Initialize-GpEditLog -LogDir $script:AppSettings.paths.logDir | Out-Null

# Real System32 paths, captured once and never reassigned - unlike the bare
# param paths, which Set-ActiveGpoProject/Start-UnsavedGpoSession redirect
# to a project's own files. File > Import always targets the real machine
# regardless of any open project, so it must use these instead.
$script:RealMachinePolPath = $MachinePolPath
$script:RealUserPolPath    = $UserPolPath
$script:RealSecEditInfPath = $SecEditInfPath
$script:RealAuditCsvPath   = $AuditCsvPath
$script:RealGptIniPath     = $GptIniPath

# Working "New Group Policy > Default" session, not yet saved: $GpoTempFiles
# tracks per-category temp files in tempfile\ ($null = category untouched,
# read from Default_gp template instead). $GpoTempSuffix is the 25-char
# random string shared by all temp files of one session. No GptIni entry:
# a project never needs GPT.ini.
$script:TempFileDir = $script:AppSettings.paths.tempDir
$script:GpoTempFiles = @{ MachinePol = $null; UserPol = $null; SecEditInf = $null; AuditCsv = $null }
$script:GpoTempSuffix = $null

# Search mode: while active, PolicyList shows multi-category search results
# instead of the currently selected tree category's contents.
$script:IsSearchActive = $false

# Full set of results from the last search plus the query text, so the view
# can be restricted to a subfolder without rerunning the search.
$script:SearchResultItems = $null
$script:LastSearchQuery = ''

# Tree node the search is restricted to, if any - updated only by an actual
# user folder click during search, never by reading $categoryTree.SelectedItem
# directly (can hold a stale, unrelated selection). $null = unrestricted.
$script:SearchScopedNode = $null

if (-not (Test-Path -LiteralPath $DataPath)) { New-Item -ItemType Directory -Path $DataPath -Force | Out-Null }
if (-not (Test-Path -LiteralPath $script:AppSettings.paths.indexDir)) { New-Item -ItemType Directory -Path $script:AppSettings.paths.indexDir -Force | Out-Null }

# Data_SecurityCatalog.json lives in the configurable indexDir, not the
# repo's data\ folder, so edits survive outside the install location.
# SecurityCatalog.ps1 was dot-sourced earlier with a repo-relative fallback
# (AppSettings not loaded yet then) - reassign and reload here. Self-heals
# from the bundled template if missing.
$script:SecurityCatalogDataPath = Join-Path $script:AppSettings.paths.indexDir 'Data_SecurityCatalog.json'
if (-not (Test-Path -LiteralPath $script:SecurityCatalogDataPath)) {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'DefaultData\Data_SecurityCatalog.json') -Destination $script:SecurityCatalogDataPath -Force
}
Import-SecurityCatalogData

# ---------------------------------------------------------------------------
# ADMX cache freshness (en-US only)
# ---------------------------------------------------------------------------
$admxFingerprint = Get-PolicyDefinitionsFingerprint -PolicyDefinitionsPath $PolicyDefinitionsPath -Language 'en-US'

$admxPath = Join-Path $script:AppSettings.paths.indexDir 'admx-index.json'
$needsRebuild = $true
if (Test-Path -LiteralPath $admxPath) {
    try {
        $existing = Get-Content -Raw -Encoding UTF8 $admxPath | ConvertFrom-Json
        if ($existing.meta.sourceFingerprint -and $existing.meta.sourceFingerprint -eq $admxFingerprint) {
            $needsRebuild = $false
            $admxIndex = $existing
        }
    }
    catch {
        Write-Warning "ADMX index unreadable, regenerating: $($_.Exception.Message)"
    }
}
if ($needsRebuild) {
    Write-Host "ADMX index missing or stale, generating..."
    & (Join-Path $PSScriptRoot 'Indexers\Build-AdmxIndex.ps1') -PolicyDefinitionsPath $PolicyDefinitionsPath -OutputPath $admxPath -SourceFingerprint $admxFingerprint
    $admxIndex = Get-Content -Raw -Encoding UTF8 $admxPath | ConvertFrom-Json
}

# secedit.inf is regenerated via `secedit /export` on every launch to
# reflect the system's effective state, not a stale file. The security
# index is then (re)built from it.
Invoke-SecEditInfExport -SecEditInfPath $SecEditInfPath | Out-Null

# Snapshot of [Registry Values] keys right after export - used on close
# (Invoke-SecEditInfApply) to detect which keys the user unchecked:
# secedit /configure never clears a value just because it's absent from the
# imported .inf (known SCE "tattooing" behavior), so those must be deleted
# explicitly.
$script:RegistryValuesBaselineKeys = @{}
$baselineGptForRegistryCleanup = Read-GptTmplInf -Path $SecEditInfPath
if ($baselineGptForRegistryCleanup.Sections.Contains('Registry Values')) {
    foreach ($k in $baselineGptForRegistryCleanup.Sections['Registry Values'].Keys) {
        $script:RegistryValuesBaselineKeys[$k] = $true
    }
}

$secPath = Join-Path $script:AppSettings.paths.indexDir 'security-index.json'
& (Join-Path $PSScriptRoot 'Indexers\Build-SecurityIndex.ps1') -SecEditInfPath $SecEditInfPath -OutputPath $secPath
$securityIndex = Get-Content -Raw -Encoding UTF8 $secPath | ConvertFrom-Json

# Advanced Audit Policy lives in its own file (audit.csv, not GptTmpl.inf):
# same always-regenerate logic as the security index (small file, uncached).
$auditIndexPath = Join-Path $script:AppSettings.paths.indexDir 'advanced-audit-index.json'
& (Join-Path $PSScriptRoot 'Indexers\Build-AdvancedAuditIndex.ps1') -AuditCsvPath $AuditCsvPath -OutputPath $auditIndexPath
$advancedAuditIndex = Get-Content -Raw -Encoding UTF8 $auditIndexPath | ConvertFrom-Json

# CIS index: same cache-freshness pattern as the ADMX index - a fingerprint
# of the Audit files folder triggers an automatic rebuild when .audit files
# change. Missing/unreadable => "CIS recommendation" tab hidden everywhere
# (Import-CisIndex returns $null).
$cisIndexPath = Join-Path $script:AppSettings.paths.indexDir 'cis-index.json'
$auditFingerprint = Get-AuditFilesFingerprint -AuditFilesPath $script:AppSettings.paths.auditFilesDir
$cisNeedsRebuild = $true
if (Test-Path -LiteralPath $cisIndexPath) {
    try {
        $existingCis = Get-Content -Raw -Encoding UTF8 $cisIndexPath | ConvertFrom-Json
        if ($existingCis.meta.sourceFingerprint -and $existingCis.meta.sourceFingerprint -eq $auditFingerprint) {
            $cisNeedsRebuild = $false
        }
    }
    catch {
        Write-Warning "CIS index unreadable, regenerating: $($_.Exception.Message)"
    }
}
if ($cisNeedsRebuild -and (Test-Path -LiteralPath $script:AppSettings.paths.auditFilesDir) -and (Get-ChildItem -LiteralPath $script:AppSettings.paths.auditFilesDir -Filter '*.audit' -File -ErrorAction SilentlyContinue)) {
    Write-Host "CIS index missing or stale, generating..."
    & (Join-Path $PSScriptRoot 'Indexers\Build-CisIndex.ps1') -AuditFilesPath $script:AppSettings.paths.auditFilesDir -OutputPath $cisIndexPath -SourceFingerprint $auditFingerprint
}
$script:CisIndex = Import-CisIndex -Path $cisIndexPath

# Active CIS profile: CisActiveProfileForColumn drives the "Recommended
# state" column; CisProfileFilter (null = no filter) further restricts the
# list to that exact profile. Never persisted, recomputed at startup from
# this machine's actual OS (WMI detection), falling back to the most
# recent OS/L1-MS profile if detection fails.
$script:CisDefaultProfile = Get-CisMachineDefaultProfile -CisIndex $script:CisIndex
if (-not $script:CisDefaultProfile) { $script:CisDefaultProfile = Get-CisDefaultProfile -CisIndex $script:CisIndex }
$script:CisActiveProfileForColumn = $script:CisDefaultProfile
$script:CisProfileFilter = $null

# Filter menu state (see Show-FilterDialog / Test-CisProfileFilterMatch /
# Test-ScopeFilterMatch / Test-KindFilterMatch / Test-StateFilterMatch).
# Defaults reproduce the old behavior: no state/scope/kind restriction, no
# CIS profile filter.
$script:FilterStateMode = 'Any'
$script:FilterScopes = @('Machine', 'User')
$script:FilterKinds = @('Admx', 'Security', 'AdvancedAudit')
$script:FilterHasCisRecOnly = $false

# Patch notes (right-hand pane + ? > Patch note).
$script:ChangelogEntries = Get-ChangelogEntries -Path (Join-Path $PSScriptRoot '..\CHANGELOG.md')
$script:PatchNotesEntryCount = 10
$script:HasLeftInitialPatchNotesView = $false

# --- Current state (registry.pol) ---------------------------------------
$machineEntries = Get-PolFileEntriesSafe -Path $MachinePolPath
$userEntries    = Get-PolFileEntriesSafe -Path $UserPolPath
$machineLookup  = New-PolLookup -Entries $machineEntries
$userLookup     = New-PolLookup -Entries $userEntries

# ---------------------------------------------------------------------------
# In-memory lookup structures for the tree/list, built from $admxIndex
# ---------------------------------------------------------------------------
$script:categoriesById   = @{}
$script:childrenByParent = @{}
$script:policiesByCategory = @{}

function Build-CategoryLookups {
    param($AdmxIndex)

    $categoriesById = @{}
    $childrenByParent = @{}
    foreach ($cat in $AdmxIndex.categories) {
        $categoriesById[$cat.id] = $cat
        $parentKey = if ($cat.parentId) { $cat.parentId } else { '$ROOT$' }
        if (-not $childrenByParent.ContainsKey($parentKey)) { $childrenByParent[$parentKey] = New-Object System.Collections.Generic.List[object] }
        $childrenByParent[$parentKey].Add($cat.id)
    }

    $policiesByCategory = @{}
    foreach ($pol in $AdmxIndex.policies) {
        if (-not $pol.categoryId) { continue }
        if (-not $policiesByCategory.ContainsKey($pol.categoryId)) { $policiesByCategory[$pol.categoryId] = New-Object System.Collections.Generic.List[object] }
        $policiesByCategory[$pol.categoryId].Add($pol)
    }

    $script:categoriesById = $categoriesById
    $script:childrenByParent = $childrenByParent
    $script:policiesByCategory = $policiesByCategory
}

Build-CategoryLookups -AdmxIndex $admxIndex

# --- Icons: Segoe MDL2 Assets glyphs (bundled with Windows, no image file
# --- to embed). Folder icon for tree categories, distinct icons for the
# --- Computer/User roots and each setting type. ---
$script:IconGlyphFolder         = [char]0xE8D5   # FolderFill
$script:IconGlyphComputer       = [char]0xE977   # PC1
$script:IconGlyphUser           = [char]0xE77B   # Contact
$script:IconGlyphAdmxSetting    = [char]0xE713   # Setting (gear)
$script:IconGlyphSecuritySetting = [char]0xE72E  # Lock
$script:IconGlyphAuditSetting   = [char]0xEA18   # Shield
$script:IconGlyphDictionary     = [char]0xE82D   # Dictionary (Overview root)

function Set-TreeNodeHeader {
    # Also sets AutomationProperties.Name explicitly: once Header is not a
    # plain string, screen readers can't derive an accessible name from it.
    param($Tvi, [string]$Text, [string]$Glyph = $null, [string]$Color = $null)
    $panel = New-Object System.Windows.Controls.StackPanel
    $panel.Orientation = 'Horizontal'
    $icon = New-Object System.Windows.Controls.TextBlock
    $icon.Text = if ($Glyph) { $Glyph } else { $script:IconGlyphFolder }
    $icon.FontFamily = 'Segoe MDL2 Assets'
    $icon.Foreground = if ($Color) { $Color } else { '#DCB67A' }
    $icon.Margin = '0,0,6,0'
    $icon.VerticalAlignment = 'Center'
    $label = New-Object System.Windows.Controls.TextBlock
    $label.Text = $Text
    $label.VerticalAlignment = 'Center'
    [void]$panel.Children.Add($icon)
    [void]$panel.Children.Add($label)
    $Tvi.Header = $panel
    [System.Windows.Automation.AutomationProperties]::SetName($Tvi, $Text)
}

function Test-PolicyMatchesScope {
    param([string]$PolicyClass, [string]$Scope)
    if ($Scope -eq 'Machine') { return ($PolicyClass -eq 'Machine' -or $PolicyClass -eq 'Both') }
    return ($PolicyClass -eq 'User' -or $PolicyClass -eq 'Both')
}

function Test-StateFilterMatch {
    # $AdmxState: raw Admx state ('Enabled'/'Disabled'/'NotConfigured'),
    # only meaningful for Kind = 'Admx' - Security/AdvancedAudit settings
    # are value-based, not enabled/disabled toggles, so they never match
    # the Enabled/Disabled modes (pass $null for those Kinds).
    param([string]$AdmxState, [bool]$IsConfigured)
    switch ($script:FilterStateMode) {
        'ConfiguredOnly' { return $IsConfigured }
        'NotConfigured'  { return -not $IsConfigured }
        'Enabled'        { return ($AdmxState -eq 'Enabled') }
        'Disabled'       { return ($AdmxState -eq 'Disabled') }
        default          { return $true }   # 'Any'
    }
}

function Test-ScopeFilterMatch {
    # $Scope: 'Machine'/'User', or $null for Security/AdvancedAudit
    # settings (always Computer-scoped in this app).
    param([string]$Scope)
    $effectiveScope = if ($Scope) { $Scope } else { 'Machine' }
    return ($script:FilterScopes -contains $effectiveScope)
}

function Test-KindFilterMatch {
    param([string]$Kind)
    return ($script:FilterKinds -contains $Kind)
}

function Test-AnyStateScopeKindFilterActive {
    # $true if the Filter menu's State/Scope/Kind dimensions currently
    # restrict the tree (used by Build-MainTreeRoots to decide whether an
    # otherwise-empty root container should still be shown).
    return (
        $script:FilterStateMode -ne 'Any' -or
        @($script:FilterScopes).Count -ne 2 -or
        @($script:FilterKinds).Count -ne 3
    )
}

function Test-CategoryHasPolicies {
    # A category only counts as "having policies" if at least one of them
    # passes the active Filter menu state/scope/kind - otherwise its folder
    # would still show up empty in the tree.
    param([string]$CategoryId, [string]$Scope, [hashtable]$Cache)

    if ($Cache.ContainsKey($CategoryId)) { return $Cache[$CategoryId] }
    $Cache[$CategoryId] = $false   # cycle guard

    $has = $false
    if ((Test-KindFilterMatch -Kind 'Admx') -and (Test-ScopeFilterMatch -Scope $Scope) -and $script:policiesByCategory.ContainsKey($CategoryId)) {
        $lookup = if ($Scope -eq 'Machine') { $machineLookup } else { $userLookup }
        foreach ($pol in $script:policiesByCategory[$CategoryId]) {
            if (-not (Test-PolicyMatchesScope -PolicyClass $pol.class -Scope $Scope)) { continue }
            if ($script:FilterStateMode -eq 'Any') { $has = $true; break }
            $state = Get-AdmxPolicyState -Policy $pol -PolLookup $lookup
            if (Test-StateFilterMatch -AdmxState $state -IsConfigured ($state -ne 'NotConfigured')) { $has = $true; break }
        }
    }
    if (-not $has -and $script:childrenByParent.ContainsKey($CategoryId)) {
        foreach ($childId in $script:childrenByParent[$CategoryId]) {
            if (Test-CategoryHasPolicies -CategoryId $childId -Scope $Scope -Cache $Cache) { $has = $true; break }
        }
    }
    $Cache[$CategoryId] = $has
    return $has
}

function Test-SecurityCategoryHasPolicies {
    # Same reasoning as Test-CategoryHasPolicies, for the static Security
    # Settings leaves (Password Policy, Audit Policy, etc.).
    param([string]$Category)
    if (-not (Test-KindFilterMatch -Kind 'Security') -or -not (Test-ScopeFilterMatch -Scope $null)) { return $false }
    if ($script:FilterStateMode -eq 'Any') { return $true }
    foreach ($setting in $script:securityIndex.settings) {
        if ($setting.category -eq $Category -and (Test-StateFilterMatch -AdmxState $null -IsConfigured $setting.isConfigured)) { return $true }
    }
    return $false
}

function Test-AdvAuditCategoryHasPolicies {
    param([string]$Category)
    if (-not (Test-KindFilterMatch -Kind 'AdvancedAudit') -or -not (Test-ScopeFilterMatch -Scope $null)) { return $false }
    if ($script:FilterStateMode -eq 'Any') { return $true }
    foreach ($setting in $script:advancedAuditIndex.settings) {
        if ($setting.category -eq $Category -and (Test-StateFilterMatch -AdmxState $null -IsConfigured $setting.isConfigured)) { return $true }
    }
    return $false
}

function New-CategoryTreeViewItem {
    # $Ancestors: list (root -> leaf order) of parent TreeViewItems, stored
    # so search can reconstruct the path to expand when navigating directly
    # from a result.
    param([string]$CategoryId, [string]$Scope, [hashtable]$Cache, [System.Collections.Generic.List[object]]$Ancestors)

    $cat = $script:categoriesById[$CategoryId]
    $tvi = New-Object System.Windows.Controls.TreeViewItem
    Set-TreeNodeHeader -Tvi $tvi -Text $cat.displayName
    $tvi.Tag = [pscustomobject]@{ Kind = 'AdmxCategory'; CategoryId = $CategoryId; Scope = $Scope }

    $key = "$CategoryId|$Scope"
    $script:TreeItemsByAdmxCategoryScope[$key] = $tvi
    $script:TreeAncestorsByKey[$key] = @($Ancestors)
    $script:AllTreeItems.Add($tvi)

    $childAncestors = New-Object System.Collections.Generic.List[object]
    $childAncestors.AddRange([object[]]@($Ancestors))
    $childAncestors.Add($tvi)

    if ($script:childrenByParent.ContainsKey($CategoryId)) {
        foreach ($childId in ($script:childrenByParent[$CategoryId] | Sort-Object { $script:categoriesById[$_].displayName })) {
            if (Test-CategoryHasPolicies -CategoryId $childId -Scope $Scope -Cache $Cache) {
                [void]$tvi.Items.Add((New-CategoryTreeViewItem -CategoryId $childId -Scope $Scope -Cache $Cache -Ancestors $childAncestors))
            }
        }
    }
    return $tvi
}

function New-SecurityLeafItem {
    param([string]$Header, [string]$Category, [System.Collections.Generic.List[object]]$Ancestors)
    $tvi = New-Object System.Windows.Controls.TreeViewItem
    Set-TreeNodeHeader -Tvi $tvi -Text $Header
    # Label keeps the plain text: Header becomes a StackPanel (icon + text)
    # once displayed, so it is no longer directly usable as a string
    # elsewhere in the code (breadcrumb, etc.).
    $tvi.Tag = [pscustomobject]@{ Kind = 'SecurityCategory'; SecurityCategory = $Category; Label = $Header }
    $script:TreeItemsBySecurityCategory[$Category] = $tvi
    $script:TreeAncestorsBySecurityCategory[$Category] = @($Ancestors)
    $script:AllTreeItems.Add($tvi)
    return $tvi
}

function New-AdvancedAuditLeafItem {
    param([string]$Header, [string]$Category, [System.Collections.Generic.List[object]]$Ancestors)
    $tvi = New-Object System.Windows.Controls.TreeViewItem
    Set-TreeNodeHeader -Tvi $tvi -Text $Header
    $tvi.Tag = [pscustomobject]@{ Kind = 'AdvancedAuditCategory'; AdvAuditCategory = $Category; Label = $Header }
    $script:TreeItemsByAdvAuditCategory[$Category] = $tvi
    $script:TreeAncestorsByAdvAuditCategory[$Category] = @($Ancestors)
    $script:AllTreeItems.Add($tvi)
    return $tvi
}

function New-StaticNode {
    # As in real gpedit.msc, only the two root nodes start collapsed
    # (IsExpanded default false).
    # $GroupId: stable identifier stored in TreeItemsByGroupId/
    # TreeAncestorsByGroupId, lets this node be found again after Rebuild-Tree.
    param([string]$Header, [string]$GroupId = $null, [System.Collections.Generic.List[object]]$Ancestors = $null, [string]$Glyph = $null, [string]$Color = $null)
    $tvi = New-Object System.Windows.Controls.TreeViewItem
    Set-TreeNodeHeader -Tvi $tvi -Text $Header -Glyph $Glyph -Color $Color
    $tvi.Tag = [pscustomobject]@{ Kind = 'Group'; Label = $Header; GroupId = $GroupId }
    $script:AllTreeItems.Add($tvi)
    if ($GroupId) {
        $script:TreeItemsByGroupId[$GroupId] = $tvi
        $script:TreeAncestorsByGroupId[$GroupId] = if ($Ancestors) { @($Ancestors) } else { @() }
    }
    return $tvi
}

function Build-MainTreeRoots {
    # Builds the two roots (Computer/User Configuration) plus the navigation
    # indexes used by search to expand/select the right node directly.
    param([hashtable]$Ui)

    $script:TreeItemsByAdmxCategoryScope = @{}
    $script:TreeAncestorsByKey = @{}
    $script:TreeItemsBySecurityCategory = @{}
    $script:TreeAncestorsBySecurityCategory = @{}
    $script:TreeItemsByAdvAuditCategory = @{}
    $script:TreeAncestorsByAdvAuditCategory = @{}
    $script:TreeItemsByGroupId = @{}
    $script:TreeAncestorsByGroupId = @{}
    $script:AllTreeItems = New-Object System.Collections.Generic.List[object]

    # "Overview": lists every setting in the console, subject to the active
    # CIS profile filter; in search mode, selecting it restores the full
    # result set (same mechanism as clicking Computer/User Configuration).
    $overviewRoot = New-StaticNode -Header $Ui.Overview -GroupId 'Overview' -Glyph $script:IconGlyphDictionary -Color '#5A6B87'

    # Loading indicator, shown only while Overview (thousands of settings,
    # a few seconds) is being rebuilt. Plain Unicode char, not Segoe MDL2,
    # so it doesn't depend on that font's glyphs.
    $script:OverviewLoadingIcon = New-Object System.Windows.Controls.TextBlock
    $script:OverviewLoadingIcon.Text = [char]0x231B
    $script:OverviewLoadingIcon.Margin = '6,0,0,0'
    $script:OverviewLoadingIcon.VerticalAlignment = 'Center'
    $script:OverviewLoadingIcon.Visibility = 'Collapsed'
    [void]$overviewRoot.Header.Children.Add($script:OverviewLoadingIcon)

    $computerRoot = New-StaticNode -Header $Ui.ComputerConfig -GroupId 'ComputerConfig' -Glyph $script:IconGlyphComputer -Color '#5A6B87'
    $computerAdmxRoot = New-StaticNode -Header $Ui.AdminTemplates -GroupId 'ComputerAdminTemplates' -Ancestors ([System.Collections.Generic.List[object]]@($computerRoot))
    $machineAncestors = [System.Collections.Generic.List[object]]@($computerRoot, $computerAdmxRoot)
    $machineCache = @{}
    foreach ($rootCatId in ($script:childrenByParent['$ROOT$'] | Sort-Object { $script:categoriesById[$_].displayName })) {
        if (Test-CategoryHasPolicies -CategoryId $rootCatId -Scope 'Machine' -Cache $machineCache) {
            [void]$computerAdmxRoot.Items.Add((New-CategoryTreeViewItem -CategoryId $rootCatId -Scope 'Machine' -Cache $machineCache -Ancestors $machineAncestors))
        }
    }
    if ($computerAdmxRoot.Items.Count -gt 0 -or -not (Test-AnyStateScopeKindFilterActive)) { [void]$computerRoot.Items.Add($computerAdmxRoot) }

    # "Windows Settings" and "Security Settings" are two distinct nested
    # folders, as in real gpedit.msc, not one combined node.
    $windowsSettingsRoot = New-StaticNode -Header $Ui.WindowsSettings -GroupId 'ComputerWindowsSettingsRoot' -Ancestors ([System.Collections.Generic.List[object]]@($computerRoot))
    $securityRoot = New-StaticNode -Header $Ui.SecuritySettings -GroupId 'ComputerSecurityRoot' -Ancestors ([System.Collections.Generic.List[object]]@($computerRoot, $windowsSettingsRoot))
    $accountPoliciesRoot = New-StaticNode -Header $Ui.AccountPolicies -GroupId 'AccountPoliciesRoot' -Ancestors ([System.Collections.Generic.List[object]]@($computerRoot, $windowsSettingsRoot, $securityRoot))
    $accountAncestors = [System.Collections.Generic.List[object]]@($computerRoot, $windowsSettingsRoot, $securityRoot, $accountPoliciesRoot)
    if (Test-SecurityCategoryHasPolicies -Category 'Password Policy') { [void]$accountPoliciesRoot.Items.Add((New-SecurityLeafItem -Header $Ui.PasswordPolicy -Category 'Password Policy' -Ancestors $accountAncestors)) }
    if (Test-SecurityCategoryHasPolicies -Category 'Account Lockout Policy') { [void]$accountPoliciesRoot.Items.Add((New-SecurityLeafItem -Header $Ui.AccountLockoutPolicy -Category 'Account Lockout Policy' -Ancestors $accountAncestors)) }
    if ($accountPoliciesRoot.Items.Count -gt 0) { [void]$securityRoot.Items.Add($accountPoliciesRoot) }

    $localPoliciesRoot = New-StaticNode -Header $Ui.LocalPolicies -GroupId 'LocalPoliciesRoot' -Ancestors ([System.Collections.Generic.List[object]]@($computerRoot, $windowsSettingsRoot, $securityRoot))
    $localAncestors = [System.Collections.Generic.List[object]]@($computerRoot, $windowsSettingsRoot, $securityRoot, $localPoliciesRoot)
    if (Test-SecurityCategoryHasPolicies -Category 'Audit Policy') { [void]$localPoliciesRoot.Items.Add((New-SecurityLeafItem -Header $Ui.AuditPolicy -Category 'Audit Policy' -Ancestors $localAncestors)) }
    if (Test-SecurityCategoryHasPolicies -Category 'User Rights Assignment') { [void]$localPoliciesRoot.Items.Add((New-SecurityLeafItem -Header $Ui.UserRightsAssignment -Category 'User Rights Assignment' -Ancestors $localAncestors)) }
    if (Test-SecurityCategoryHasPolicies -Category 'Security Options') { [void]$localPoliciesRoot.Items.Add((New-SecurityLeafItem -Header $Ui.SecurityOptions -Category 'Security Options' -Ancestors $localAncestors)) }
    if ($localPoliciesRoot.Items.Count -gt 0) { [void]$securityRoot.Items.Add($localPoliciesRoot) }

    $advAuditConfigRoot = New-StaticNode -Header $Ui.AdvancedAuditPolicyConfig -GroupId 'AdvAuditConfigRoot' -Ancestors ([System.Collections.Generic.List[object]]@($computerRoot, $windowsSettingsRoot, $securityRoot))
    $advAuditObjectRoot = New-StaticNode -Header $Ui.AdvancedAuditPolicyObject -GroupId 'AdvAuditObjectRoot' -Ancestors ([System.Collections.Generic.List[object]]@($computerRoot, $windowsSettingsRoot, $securityRoot, $advAuditConfigRoot))
    $advAuditAncestors = [System.Collections.Generic.List[object]]@($computerRoot, $windowsSettingsRoot, $securityRoot, $advAuditConfigRoot, $advAuditObjectRoot)
    foreach ($catKey in $script:AdvancedAuditCategoryOrder) {
        if (-not (Test-AdvAuditCategoryHasPolicies -Category $catKey)) { continue }
        $catHeader = $Ui["AdvAudit$catKey"]
        [void]$advAuditObjectRoot.Items.Add((New-AdvancedAuditLeafItem -Header $catHeader -Category $catKey -Ancestors $advAuditAncestors))
    }
    if ($advAuditObjectRoot.Items.Count -gt 0) { [void]$advAuditConfigRoot.Items.Add($advAuditObjectRoot) }
    if ($advAuditConfigRoot.Items.Count -gt 0) { [void]$securityRoot.Items.Add($advAuditConfigRoot) }

    if ($securityRoot.Items.Count -gt 0) { [void]$windowsSettingsRoot.Items.Add($securityRoot) }
    if ($windowsSettingsRoot.Items.Count -gt 0 -or -not (Test-AnyStateScopeKindFilterActive)) { [void]$computerRoot.Items.Add($windowsSettingsRoot) }

    $userRoot = New-StaticNode -Header $Ui.UserConfig -GroupId 'UserConfig' -Glyph $script:IconGlyphUser -Color '#5A6B87'
    $userAdmxRoot = New-StaticNode -Header $Ui.AdminTemplates -GroupId 'UserAdminTemplates' -Ancestors ([System.Collections.Generic.List[object]]@($userRoot))
    $userAncestors = [System.Collections.Generic.List[object]]@($userRoot, $userAdmxRoot)
    $userCache = @{}
    foreach ($rootCatId in ($script:childrenByParent['$ROOT$'] | Sort-Object { $script:categoriesById[$_].displayName })) {
        if (Test-CategoryHasPolicies -CategoryId $rootCatId -Scope 'User' -Cache $userCache) {
            [void]$userAdmxRoot.Items.Add((New-CategoryTreeViewItem -CategoryId $rootCatId -Scope 'User' -Cache $userCache -Ancestors $userAncestors))
        }
    }
    if ($userAdmxRoot.Items.Count -gt 0 -or -not (Test-AnyStateScopeKindFilterActive)) { [void]$userRoot.Items.Add($userAdmxRoot) }

    return [pscustomobject]@{ OverviewRoot = $overviewRoot; ComputerRoot = $computerRoot; UserRoot = $userRoot }
}

# --- Loading the XAML window ---------------------------------------------
# MainWindow and the shared style both live in AllWindows.Reference.xaml;
# Get-MergedXamlWindowNode/Get-MergedXamlStyleNode extract the desired node.
$mainWindowNode = Get-MergedXamlWindowNode -ScriptRoot $PSScriptRoot -Name 'MainWindow'
$window = Import-XamlFragment -Node $mainWindowNode

# Loaded and merged separately rather than via <ResourceDictionary
# Source=...>, because XamlReader.Load here has no BaseUri to resolve a
# relative path. $script: scope so Show-AdmxEditDialog can reuse it to
# style dialog windows too.
$styleNode = Get-MergedXamlStyleNode -ScriptRoot $PSScriptRoot
$script:ModernStyle = Import-XamlFragment -Node $styleNode
$window.Resources.MergedDictionaries.Add($script:ModernStyle)

$categoryTree      = $window.FindName('CategoryTree')
$policyList        = $window.FindName('PolicyList')
$categoryPathLabel = $window.FindName('CategoryPathLabel')
$statusLabel       = $window.FindName('StatusLabel')
$searchBox         = $window.FindName('SearchBox')
$searchFieldCombo  = $window.FindName('SearchFieldCombo')
$searchFieldAnyItem = $window.FindName('SearchFieldAnyItem')
$searchFieldNameItem = $window.FindName('SearchFieldNameItem')
$searchFieldDescriptionItem = $window.FindName('SearchFieldDescriptionItem')
$searchFieldKeyItem = $window.FindName('SearchFieldKeyItem')
$searchFieldCisNumberItem = $window.FindName('SearchFieldCisNumberItem')
$searchButton      = $window.FindName('SearchButton')
$clearSearchButton = $window.FindName('ClearSearchButton')
$columnName        = $window.FindName('ColumnName')
$columnCategory    = $window.FindName('ColumnCategory')
$columnState       = $window.FindName('ColumnState')
$columnScope       = $window.FindName('ColumnScope')
$columnCis         = $window.FindName('ColumnCis')
$columnRecommendedState = $window.FindName('ColumnRecommendedState')
$columnCisStates   = $window.FindName('ColumnCisStates')
$activeProfileLabel = $window.FindName('ActiveProfileLabel')
$activeProjectLabel = $window.FindName('ActiveProjectLabel')
$logPathLabel      = $window.FindName('LogPathLabel')
$saveNowButton     = $window.FindName('SaveNowButton')
$detailGroupBox    = $window.FindName('DetailGroupBox')
$detailTextBox     = $window.FindName('DetailTextBox')
$fileMenu          = $window.FindName('FileMenu')
$fileNewMenuItem   = $window.FindName('FileNewMenuItem')
$fileSaveMenuItem  = $window.FindName('FileSaveMenuItem')
$fileOpenMenuItem  = $window.FindName('FileOpenMenuItem')
$fileImportMenuItem = $window.FindName('FileImportMenuItem')
$fileExportMenuItem = $window.FindName('FileExportMenuItem')
$fileOptionsMenuItem = $window.FindName('FileOptionsMenuItem')
$fileExitMenuItem  = $window.FindName('FileExitMenuItem')
$viewMenu          = $window.FindName('ViewMenu')
$viewColumnsMenuItem = $window.FindName('ViewColumnsMenuItem')
$filterMenu        = $window.FindName('FilterMenu')
$helpMenu          = $window.FindName('HelpMenu')
$helpAboutMenuItem = $window.FindName('HelpAboutMenuItem')
$helpPatchNoteMenuItem = $window.FindName('HelpPatchNoteMenuItem')
$helpLogsMenuItem  = $window.FindName('HelpLogsMenuItem')
$patchNotesPanel   = $window.FindName('PatchNotesPanel')
$patchNotesTitleLabel = $window.FindName('PatchNotesTitleLabel')
$patchNotesTextBlock = $window.FindName('PatchNotesTextBlock')
$mainContentGrid   = $window.FindName('MainContentGrid')

function Get-CurrentUi { return Get-UiStrings }

function Update-StaticUiText {
    param([hashtable]$Ui)
    $window.Title = $Ui.WindowTitle
    $searchBox.Text = $Ui.SearchPlaceholder
    $searchFieldAnyItem.Content = $Ui.SearchFieldAny
    $searchFieldNameItem.Content = $Ui.SearchFieldName
    $searchFieldDescriptionItem.Content = $Ui.SearchFieldDescription
    $searchFieldKeyItem.Content = $Ui.SearchFieldKey
    $searchFieldCisNumberItem.Content = $Ui.SearchFieldCisNumber
    $searchButton.Content = $Ui.SearchButton
    $clearSearchButton.Content = $Ui.ClearSearchButton
    $columnName.Header = $Ui.ColumnName
    $columnCategory.Header = $Ui.ColumnCategory
    $columnState.Header = $Ui.ColumnState
    $columnScope.Header = $Ui.ColumnScope
    $columnCis.Header = $Ui.ColumnCis
    $columnRecommendedState.Header = $Ui.ColumnRecommendedState
    $columnCisStates.Header = $Ui.ColumnCisStates
    $saveNowButton.Content = $Ui.SaveNowButton
    $logPathLabel.Text = ($Ui.LogPathFormat -f $script:LogFilePath)
    $categoryPathLabel.Text = $Ui.SelectCategoryPrompt
    $statusLabel.Text = ($Ui.StatusIndexSummary -f $admxIndex.policies.Count, $admxIndex.categories.Count, $securityIndex.settings.Count)
    $detailGroupBox.Header = $Ui.DetailGroupBoxHeader
    $detailTextBox.Text = $Ui.DetailNoSelection

    $fileMenu.Header = $Ui.MenuFile
    $fileNewMenuItem.Header = $Ui.MenuFileNew
    $fileSaveMenuItem.Header = $Ui.MenuFileSave
    $fileOpenMenuItem.Header = $Ui.MenuFileOpen
    $fileImportMenuItem.Header = $Ui.MenuFileImport
    $fileExportMenuItem.Header = $Ui.MenuFileExport
    $fileExitMenuItem.Header = $Ui.MenuFileExit
    $viewMenu.Header = $Ui.MenuView
    $viewColumnsMenuItem.Header = $Ui.MenuViewColumns
    $helpMenu.Header = $Ui.MenuHelp
    $helpAboutMenuItem.Header = $Ui.MenuHelpAbout
    $helpPatchNoteMenuItem.Header = $Ui.MenuHelpPatchNote
    $patchNotesTitleLabel.Text = $Ui.PatchNotesTitle
    Update-FilterMenuLabel -Ui $Ui
    if (-not $script:HasLeftInitialPatchNotesView) { Update-PatchNotesPanelContent }
}

function Rebuild-Tree {
    param([hashtable]$Ui)
    $categoryTree.Items.Clear()
    $roots = Build-MainTreeRoots -Ui $Ui
    [void]$categoryTree.Items.Add($roots.OverviewRoot)
    [void]$categoryTree.Items.Add($roots.ComputerRoot)
    [void]$categoryTree.Items.Add($roots.UserRoot)
}

function Select-FilteredItems {
    <#
        Filter menu: applies Scope/Kind/State on top of the already-built
        item list (Kind/Scope/IsConfigured are set on every item - see
        Update-PolicyList/Invoke-Search). State's Enabled/Disabled modes
        are reconstructed from StateLabel for Admx items only, since raw
        Admx state isn't kept on the item itself (see Test-StateFilterMatch).
        Leading comma prevents PowerShell unwrapping an empty result to
        $null (which would crash callers doing "$null.Count" under
        StrictMode).
    #>
    param($Items)
    $ui = Get-CurrentUi
    $filtered = [System.Collections.Generic.List[object]]@($Items | Where-Object {
        $item = $_
        if (-not (Test-ScopeFilterMatch -Scope $item.Scope)) { return $false }
        if (-not (Test-KindFilterMatch -Kind $item.Kind)) { return $false }
        $admxState = $null
        if ($item.Kind -eq 'Admx') {
            $admxState = if ($item.StateLabel -eq $ui.StateEnabled) { 'Enabled' }
                elseif ($item.StateLabel -eq $ui.StateDisabled) { 'Disabled' }
                else { 'NotConfigured' }
        }
        return (Test-StateFilterMatch -AdmxState $admxState -IsConfigured $item.IsConfigured)
    })
    return , $filtered
}

function Refresh-ListForCisStateChange {
    # Reapplies the current list after a CIS profile/filter change so the
    # "Recommended state" column updates immediately without reopening.
    if ($script:IsSearchActive) {
        if ($script:LastSearchQuery) {
            Invoke-Search -Query $script:LastSearchQuery -PreserveScope
            if ($script:SearchScopedNode) { Update-SearchResultsForSelectedCategory }
        }
    }
    elseif ($categoryTree.SelectedItem) {
        Update-PolicyList
    }
}

function Test-CisProfileFilterMatch {
    # $true if $CisEntry passes both the "has a CIS recommendation" filter
    # and the profile filter (no profile filter is active, or $CisEntry
    # has a recommendation for the filtered profile).
    param($CisEntry)
    if ($script:FilterHasCisRecOnly -and $null -eq $CisEntry) { return $false }
    if ($null -eq $script:CisProfileFilter) { return $true }
    return ($null -ne (Get-CisRecommendationValueForProfile -CisEntry $CisEntry -ActiveProfile $script:CisProfileFilter))
}

function Get-CisValueLabelForRow {
    <#
        Feeds the "CIS R. Value" column. Matches exactly against
        CisActiveProfileForColumn - empty if the setting doesn't cover that
        exact profile, even if it covers a different one (e.g. Server
        benchmark on a workstation), to avoid a misleading borrowed value.
    #>
    param($CisEntry, [hashtable]$Ui)

    return Get-CisRecommendationValueForProfile -CisEntry $CisEntry -ActiveProfile $script:CisActiveProfileForColumn -Ui $Ui
}

function Get-CisRowLabels {
    <#
        Computes all 3 CIS columns together from one resolution so they
        stay consistent (CisLabel "Yes" must never coincide with empty
        RecommendedStateLabel/CisStatesLabel, or vice versa).
    #>
    param($CisEntry, [hashtable]$Ui)

    $valueLabel = Get-CisValueLabelForRow -CisEntry $CisEntry -Ui $Ui
    return [pscustomobject]@{
        CisLabel              = if ($valueLabel) { $Ui.CisYes } else { $Ui.CisNo }
        RecommendedStateLabel = $valueLabel
        CisStatesLabel        = if ($valueLabel) { Get-CisRecommendationStateText -CisEntry $CisEntry } else { $null }
    }
}

function Update-TreeVisibilityForCisFilter {
    <#
        Filtering by CIS profile and/or "has a CIS recommendation" must not
        leave empty tree nodes - same principle as search filtering
        (Update-TreeVisibilityForSearch) but computed over all settings,
        both scopes. Restores full tree if no filter is active. State/
        Scope/Kind filtering is handled separately, by rebuilding the tree
        itself (see Test-CategoryHasPolicies and the FilterMenu handler).
    #>
    if ($null -eq $script:CisProfileFilter -and -not $script:FilterHasCisRecOnly) {
        Show-AllTreeItems
        return
    }

    $keepVisible = @{}

    foreach ($pol in $script:admxIndex.policies) {
        $cisRec = Get-CisRecommendationForRegistry -CisIndex $script:CisIndex -RegistryKey $pol.registryKey -ValueName $pol.valueName
        if (-not (Test-CisProfileFilterMatch -CisEntry $cisRec)) { continue }
        foreach ($scope in @('Machine', 'User')) {
            if (-not (Test-PolicyMatchesScope -PolicyClass $pol.class -Scope $scope)) { continue }
            $treeKey = "$($pol.categoryId)|$scope"
            if ($script:TreeItemsByAdmxCategoryScope.ContainsKey($treeKey)) {
                Add-TreeKeepVisible -KeepSet $keepVisible -Node $script:TreeItemsByAdmxCategoryScope[$treeKey] -Ancestors $script:TreeAncestorsByKey[$treeKey]
            }
        }
    }

    foreach ($setting in $script:securityIndex.settings) {
        $cisRec = Get-CisRecommendationForSecuritySetting -CisIndex $script:CisIndex -Section $setting.section -Name $setting.name
        if (-not (Test-CisProfileFilterMatch -CisEntry $cisRec)) { continue }
        if ($script:TreeItemsBySecurityCategory.ContainsKey($setting.category)) {
            Add-TreeKeepVisible -KeepSet $keepVisible -Node $script:TreeItemsBySecurityCategory[$setting.category] -Ancestors $script:TreeAncestorsBySecurityCategory[$setting.category]
        }
    }

    foreach ($setting in $script:advancedAuditIndex.settings) {
        $cisRec = Get-CisRecommendationForAuditSubcategory -CisIndex $script:CisIndex -SubcategoryNameEn $setting.name
        if (-not (Test-CisProfileFilterMatch -CisEntry $cisRec)) { continue }
        if ($script:TreeItemsByAdvAuditCategory.ContainsKey($setting.category)) {
            Add-TreeKeepVisible -KeepSet $keepVisible -Node $script:TreeItemsByAdvAuditCategory[$setting.category] -Ancestors $script:TreeAncestorsByAdvAuditCategory[$setting.category]
        }
    }

    Update-TreeVisibilityForSearch -KeepSet $keepVisible
}

function Get-CisProfileDisplayText {
    # Human-readable CIS profile label (e.g. "Microsoft Windows 11
    # Stand-alone v5.0.0 L1"), feeds ActiveProfileLabel in the status bar.
    param($ProfileSpec)
    if ($null -eq $ProfileSpec) { return $null }
    $text = "$($ProfileSpec.Benchmark) v$($ProfileSpec.Version) $($ProfileSpec.Level)"
    if ($ProfileSpec.Role) { $text += " $($ProfileSpec.Role)" }
    return $text
}

function Update-ActiveProfileLabel {
    # Status bar (bottom of the console): name of the CIS profile currently
    # active for the "Recommended state" column - reflects either the
    # explicitly chosen filter (View > Profile) or the machine's default
    # profile otherwise (see Get-CisMachineDefaultProfile). Empty if no CIS
    # index is loaded (CisActiveProfileForColumn then stays $null).
    $ui = Get-CurrentUi
    $text = Get-CisProfileDisplayText -ProfileSpec $script:CisActiveProfileForColumn
    $activeProfileLabel.Text = if ($text) { $ui.ActiveCisProfileFormat -f $text } else { '' }
}

# --- Advanced menu: off-machine GPO projects (see
# plan-gpedit-advanced-generate-gpo.md) ------------------------------------

function Update-ActiveProjectLabel {
    # Status bar AND window title: 3 states - no project (empty), a "New
    # Group Policy" session in progress but not yet saved (generic text, no
    # name, title unchanged), or a saved/opened project (real name). Edits
    # made once a project is saved/opened only reach its real files when
    # "Save now" is clicked (see Save-GpoProjectChanges, Update-SaveNowButtonVisibility)
    # - there is no auto-save indicator to show here anymore.
    $ui = Get-CurrentUi
    if ($script:ActiveProject -and $script:ActiveProject.Saved) {
        $activeProjectLabel.Text = ($ui.ActiveProjectFormat -f $script:ActiveProject.Name)
        $window.Title = ($ui.WindowTitleWithProjectFormat -f $ui.WindowTitle, $script:ActiveProject.Name)
    } elseif ($script:ActiveProject) {
        $activeProjectLabel.Text = $ui.UnsavedProjectStatusText
        $window.Title = $ui.WindowTitle
    } else {
        $activeProjectLabel.Text = ''
        $window.Title = $ui.WindowTitle
    }
}

function Update-GpoDerivedState {
    # Rebuilds lookups/indexes from the current paths and refreshes the
    # displayed list - shared by Set-ActiveGpoProject and
    # Start-UnsavedGpoSession to avoid duplicating this logic.
    $newMachineEntries = Get-PolFileEntriesSafe -Path $script:MachinePolPath
    $newUserEntries = Get-PolFileEntriesSafe -Path $script:UserPolPath
    $script:machineLookup = New-PolLookup -Entries $newMachineEntries
    $script:userLookup = New-PolLookup -Entries $newUserEntries

    $secPath = Join-Path $script:AppSettings.paths.indexDir 'security-index.json'
    & (Join-Path $PSScriptRoot 'Indexers\Build-SecurityIndex.ps1') -SecEditInfPath $script:SecEditInfPath -OutputPath $secPath
    $script:securityIndex = Get-Content -Raw -Encoding UTF8 $secPath | ConvertFrom-Json

    $auditIndexPath = Join-Path $script:AppSettings.paths.indexDir 'advanced-audit-index.json'
    & (Join-Path $PSScriptRoot 'Indexers\Build-AdvancedAuditIndex.ps1') -AuditCsvPath $script:AuditCsvPath -OutputPath $auditIndexPath
    $script:advancedAuditIndex = Get-Content -Raw -Encoding UTF8 $auditIndexPath | ConvertFrom-Json

    Refresh-ListForCisStateChange
}

function Disable-GpoAdvancedMenusForActiveSession {
    # Only one project/session per launch: New/Open disable themselves once
    # a GPO session is active.
    $fileNewMenuItem.IsEnabled = $false
    $fileOpenMenuItem.IsEnabled = $false
}

function Update-SaveNowButtonVisibility {
    # "Save now" only makes sense with an active project that has pending
    # unpushed changes - outside a project the app writes straight to the
    # real system.
    $saveNowButton.Visibility = if ($script:ActiveProject -and $script:ProjectDirty) { 'Visible' } else { 'Collapsed' }
}

function New-GpoTempSuffix {
    # 25 random chars shared by every temp file of a session.
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    return -join (1..25 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}

function Get-OrCreateGpoTempFile {
    <#
        Lazily materializes the temp working file for a category on its
        first edit, seeded from $SeedSource if present. $script:GpoTempFiles
        remembers the path so an already-edited file is never recreated.
    #>
    param([Parameter(Mandatory)][ValidateSet('MachinePol', 'UserPol', 'SecEditInf', 'AuditCsv')][string]$Key, [string]$SeedSource)

    if ($script:GpoTempFiles[$Key]) { return $script:GpoTempFiles[$Key] }

    if (-not (Test-Path -LiteralPath $script:TempFileDir)) { New-Item -ItemType Directory -Path $script:TempFileDir -Force | Out-Null }
    if (-not $script:GpoTempSuffix) { $script:GpoTempSuffix = New-GpoTempSuffix }

    $fileName = switch ($Key) {
        'MachinePol'  { "temp_$($script:GpoTempSuffix).pol" }
        'UserPol'     { "temp_$($script:GpoTempSuffix)_user.pol" }
        'SecEditInf'  { "temp_$($script:GpoTempSuffix).inf" }
        'AuditCsv'    { "temp_$($script:GpoTempSuffix).csv" }
    }
    $tempPath = Join-Path $script:TempFileDir $fileName
    if ($SeedSource -and (Test-Path -LiteralPath $SeedSource)) {
        Copy-Item -LiteralPath $SeedSource -Destination $tempPath -Force
    }
    $script:GpoTempFiles[$Key] = $tempPath
    return $tempPath
}

function Remove-GpoTempFiles {
    # Deletes every temp file materialized this session and resets state.
    foreach ($key in @($script:GpoTempFiles.Keys)) {
        $p = $script:GpoTempFiles[$key]
        if ($p -and (Test-Path -LiteralPath $p)) { Remove-Item -LiteralPath $p -Force }
        $script:GpoTempFiles[$key] = $null
    }
    $script:GpoTempSuffix = $null
}

function Set-ActiveGpoProject {
    <#
        Central switch-over to a project saved on disk - called by
        Open-GpoProject and by Save-GpoProjectAs (-PreserveWorkingPaths:
        working paths already point at what was just copied into the
        project folder, nothing to reassign). $Files is the relative-path
        map persisted in <name>_Info.xml, kept on $script:ActiveProject.Files
        so Save-GpoProjectChanges knows where each file belongs. No
        $script:GptIniPath here: a project never writes GPT.ini.
    #>
    param(
        [Parameter(Mandatory)][string]$Dir,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][hashtable]$Files,
        [switch]$PreserveWorkingPaths
    )

    if (-not $PreserveWorkingPaths) {
        $script:MachinePolPath = Join-Path $Dir $Files.machinePol
        $script:UserPolPath = Join-Path $Dir $Files.userPol
        $script:AuditCsvPath = Join-Path $Dir $Files.auditCsv
        $script:SecEditInfPath = Join-Path $Dir $Files.secEditInf
    }
    $script:ActiveProject = @{ Dir = $Dir; Name = $Name; Saved = $true; Files = $Files }
    $script:ProjectDirty = $false

    if (-not $PreserveWorkingPaths) { Update-GpoDerivedState }
    Disable-GpoAdvancedMenusForActiveSession
    # File > Save stays enabled once a project is saved/opened - it now
    # doubles as "Save now" from the menu.
    $fileSaveMenuItem.IsEnabled = $true
    Update-SaveNowButtonVisibility

    Update-ActiveProjectLabel
}

function Start-UnsavedGpoSession {
    <#
        "Advanced > New Group Policy > Default": loads the Default template
        for editing without creating anything on disk. Edits materialize
        temp files (Get-OrCreateGpoTempFile); File > Save first writes to a
        real project folder.
    #>
    $script:ActiveProject = @{ Dir = $null; Name = $null; Saved = $false }
    $script:ProjectDirty = $false
    $script:GpoTempFiles = @{ MachinePol = $null; UserPol = $null; SecEditInf = $null; AuditCsv = $null }
    $script:GpoTempSuffix = $null

    # Default.pol covers only Machine scope - $UserPolPath points directly
    # at its future temp location (absent until materialized, tolerated by
    # Get-PolFileEntriesSafe).
    $script:MachinePolPath = Join-Path $script:DefaultGpPath 'Default.pol'
    $script:UserPolPath = Join-Path $script:TempFileDir 'temp_unsaved_user.pol'
    $script:SecEditInfPath = Join-Path $script:DefaultGpPath 'Default.cfg'
    $script:AuditCsvPath = Join-Path $script:DefaultGpPath 'Default.csv'

    Update-GpoDerivedState
    Disable-GpoAdvancedMenusForActiveSession
    $fileSaveMenuItem.IsEnabled = $true
    Update-SaveNowButtonVisibility

    Update-ActiveProjectLabel
}

function Copy-GpoWorkingFile {
    # Best-effort copy (missing source tolerated), works for both a temp
    # file and an unchanged Default_gp template.
    param([string]$CurrentPath, [Parameter(Mandatory)][string]$Destination)
    if ($CurrentPath -and (Test-Path -LiteralPath $CurrentPath)) {
        Copy-Item -LiteralPath $CurrentPath -Destination $Destination -Force
    }
}

function Save-GpoProjectManifest {
    <#
        Writes the project manifest as XML (<name>_Info.xml). Built via
        XmlDocument (not string interpolation) so a project name containing
        XML-special characters, which SaveFileDialog doesn't prevent, is
        escaped correctly.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][hashtable]$Files)

    $xml = New-Object System.Xml.XmlDocument
    $xml.AppendChild($xml.CreateXmlDeclaration('1.0', 'UTF-8', $null)) | Out-Null
    $root = $xml.CreateElement('ProjectInfo')
    $xml.AppendChild($root) | Out-Null

    $nameEl = $xml.CreateElement('Name')
    $nameEl.InnerText = $Name
    $root.AppendChild($nameEl) | Out-Null

    $createdEl = $xml.CreateElement('CreatedAt')
    $createdEl.InnerText = (Get-Date).ToString('o')
    $root.AppendChild($createdEl) | Out-Null

    $filesEl = $xml.CreateElement('Files')
    $root.AppendChild($filesEl) | Out-Null
    foreach ($pair in @(
        @{ Key = 'MachinePol'; Value = $Files.machinePol },
        @{ Key = 'UserPol'; Value = $Files.userPol },
        @{ Key = 'SecEditInf'; Value = $Files.secEditInf },
        @{ Key = 'AuditCsv'; Value = $Files.auditCsv }
    )) {
        $el = $xml.CreateElement($pair.Key)
        $el.InnerText = $pair.Value
        $filesEl.AppendChild($el) | Out-Null
    }

    $xml.Save($Path)
}

function Get-GpoProjectManifest {
    <#
        Reads a <name>_Info.xml manifest back. Returns $null on anything
        malformed/incomplete so the caller can show its own "invalid
        project" message.
    #>
    param([Parameter(Mandatory)][string]$Path)

    try {
        $xml = New-Object System.Xml.XmlDocument
        $xml.Load($Path)
        $root = $xml.ProjectInfo
        $name = $root.Name
        $filesNode = $root.Files
        if (-not $name -or -not $filesNode) { return $null }
        $files = @{
            machinePol = $filesNode.MachinePol
            userPol    = $filesNode.UserPol
            secEditInf = $filesNode.SecEditInf
            auditCsv   = $filesNode.AuditCsv
        }
        if (-not $files.machinePol -or -not $files.userPol -or -not $files.secEditInf -or -not $files.auditCsv) { return $null }
        return [pscustomobject]@{ Name = $name; Files = $files }
    }
    catch {
        return $null
    }
}

function Save-GpoProjectAs {
    <#
        "File > Save": only effective during an unsaved "New Group Policy"
        session. Opens SaveFileDialog; the chosen name becomes the project
        folder name. Writes <name>_Info.xml, then switches to
        Set-ActiveGpoProject -PreserveWorkingPaths so already-materialized
        temp files keep being used as-is.
    #>
    if (-not $script:ActiveProject -or $script:ActiveProject.Saved) { return }
    $ui = Get-CurrentUi

    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Title = $ui.SaveGpoDialogTitle
    $dialog.Filter = 'GPedit Project (*.gpoproj)|*.gpoproj'
    $dialog.FileName = ''
    if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

    $name = [System.IO.Path]::GetFileNameWithoutExtension($dialog.FileName)
    $parentDir = Split-Path -Parent $dialog.FileName
    $projectDir = Join-Path $parentDir $name

    if ($name.Length -eq 0 -or (Test-Path -LiteralPath $projectDir)) {
        [System.Windows.MessageBox]::Show(($ui.NewProjectNameExistsMessage -f $name), $ui.ErrorTitle, 'OK', 'Warning') | Out-Null
        return
    }

    $files = @{
        machinePol = 'Machine\registry.pol'
        userPol    = 'User\registry.pol'
        secEditInf = 'secedit.inf'
        auditCsv   = 'Machine\Microsoft\Windows NT\Audit\audit.csv'
    }

    New-Item -ItemType Directory -Path $projectDir -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $projectDir 'Machine') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $projectDir 'User') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $projectDir 'Machine\Microsoft\Windows NT\Audit') -Force | Out-Null

    Copy-GpoWorkingFile -CurrentPath $script:MachinePolPath -Destination (Join-Path $projectDir $files.machinePol)
    Copy-GpoWorkingFile -CurrentPath $script:UserPolPath -Destination (Join-Path $projectDir $files.userPol)
    Copy-GpoWorkingFile -CurrentPath $script:SecEditInfPath -Destination (Join-Path $projectDir $files.secEditInf)
    Copy-GpoWorkingFile -CurrentPath $script:AuditCsvPath -Destination (Join-Path $projectDir $files.auditCsv)

    Save-GpoProjectManifest -Path (Join-Path $projectDir "$($name)_Info.xml") -Name $name -Files $files

    Set-ActiveGpoProject -Dir $projectDir -Name $name -Files $files -PreserveWorkingPaths
    Write-GpEditProjectLog -Action 'Created' -ProjectName $name
}

function Save-GpoProjectChanges {
    <#
        "Save now": pushes current working files (temp files for edited
        categories, untouched project files otherwise) onto the active
        project's real files, using the path map in $script:ActiveProject.Files.
        Working paths and temp files are left untouched afterward.
    #>
    if (-not $script:ActiveProject -or -not $script:ActiveProject.Saved) { return }
    $dir = $script:ActiveProject.Dir
    $files = $script:ActiveProject.Files

    Copy-GpoWorkingFile -CurrentPath $script:MachinePolPath -Destination (Join-Path $dir $files.machinePol)
    Copy-GpoWorkingFile -CurrentPath $script:UserPolPath -Destination (Join-Path $dir $files.userPol)
    Copy-GpoWorkingFile -CurrentPath $script:SecEditInfPath -Destination (Join-Path $dir $files.secEditInf)
    Copy-GpoWorkingFile -CurrentPath $script:AuditCsvPath -Destination (Join-Path $dir $files.auditCsv)

    $script:ProjectDirty = $false
    Update-SaveNowButtonVisibility
}

function Invoke-SaveGpoProjectNow {
    <#
        Shared by the "Save now" button and File > Save once a project is
        active: pushes pending edits (Save-GpoProjectChanges) and confirms
        success/failure with a popup.
    #>
    if (-not $script:ActiveProject -or -not $script:ActiveProject.Saved) { return }
    $ui = Get-CurrentUi
    try {
        Save-GpoProjectChanges
        [System.Windows.MessageBox]::Show($ui.SaveNowSuccessMessage, $ui.InfoTitle, 'OK', 'Information') | Out-Null
    }
    catch {
        Show-WriteErrorMessage -Ui $ui -ErrorText $_.Exception.Message
    }
}

function New-GpoProject {
    <#
        "Advanced > New Group Policy": Default loads the template directly
        for editing (Start-UnsavedGpoSession), saved only via File > Save.
    #>
    $ui = Get-CurrentUi
    $choice = Show-NewGpoDialog -Owner $window -ScriptRoot $PSScriptRoot -Ui $ui
    if (-not $choice) { return }
    Start-UnsavedGpoSession
}

function Open-GpoProject {
    <#
        "Advanced > Open Group Policy": no admin check, no copy/write -
        just points the app at an existing project folder, validated by a
        readable <name>_Info.xml naming all 4 real files. Nothing is
        imported implicitly beyond what that map lists.
    #>
    $ui = Get-CurrentUi
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title = $ui.OpenGpoFolderDialogTitle
    $dialog.Filter = 'GPedit Project Manifest (*_Info.xml)|*_Info.xml'

    if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

    $manifestPath = $dialog.FileName
    $selectedPath = Split-Path -Parent $manifestPath

    $manifest = Get-GpoProjectManifest -Path $manifestPath
    if (-not $manifest) {
        [System.Windows.MessageBox]::Show($ui.OpenGpoInvalidProjectMessage, $ui.ErrorTitle, 'OK', 'Warning') | Out-Null
        return
    }

    Set-ActiveGpoProject -Dir $selectedPath -Name $manifest.Name -Files $manifest.Files
}

function Export-GpoProjectFiles {
    <#
        "File > Export": builds the exact same folder/file layout as
        Save-GpoProjectAs (Machine\registry.pol, User\registry.pol,
        secedit.inf, Machine\Microsoft\Windows NT\Audit\audit.csv, plus a
        <name>_Info.xml manifest) at a location chosen via the same
        SaveFileDialog trick used to save a project. Works in every app
        state, from two different sources:
        - a SAVED project is active ($script:ActiveProject.Saved): first
          asks to push any pending temp-file edits into the real project
          folder (same effect as "Save now"), since the export always
          reads FROM the project's own real files, never the temp working
          paths directly - skipping this could silently export stale data.
          Cancelling this confirmation aborts the export entirely.
        - anything else (no project active, OR an unsaved "New Group
          Policy" session in progress): copies straight from the current
          working paths. For "no project" these already ARE the real
          system files (secedit.inf, audit.csv, registry.pol); for an
          unsaved session they are the session's temp/Default_gp files -
          either way there is no separate "saved" copy to prefer over
          them, so both cases are handled identically.
    #>
    $ui = Get-CurrentUi
    $isSavedProject = $script:ActiveProject -and $script:ActiveProject.Saved

    if ($isSavedProject) {
        $confirm = [System.Windows.MessageBox]::Show($ui.ExportConfirmSaveMessage, $ui.ExportConfirmSaveTitle, 'OKCancel', 'Question')
        if ($confirm -ne [System.Windows.MessageBoxResult]::OK) { return }
        try {
            Save-GpoProjectChanges
        }
        catch {
            Show-WriteErrorMessage -Ui $ui -ErrorText $_.Exception.Message
            return
        }
    }

    $dialog = New-Object System.Windows.Forms.SaveFileDialog
    $dialog.Title = $ui.ExportGpoDialogTitle
    $dialog.Filter = 'GPedit Project (*.gpoproj)|*.gpoproj'
    $dialog.InitialDirectory = $script:AppSettings.paths.importExportDir
    $dialog.FileName = ''
    if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

    $name = [System.IO.Path]::GetFileNameWithoutExtension($dialog.FileName)
    $parentDir = Split-Path -Parent $dialog.FileName
    $exportDir = Join-Path $parentDir $name

    if ($name.Length -eq 0 -or (Test-Path -LiteralPath $exportDir)) {
        [System.Windows.MessageBox]::Show(($ui.NewProjectNameExistsMessage -f $name), $ui.ErrorTitle, 'OK', 'Warning') | Out-Null
        return
    }

    $files = @{
        machinePol = 'Machine\registry.pol'
        userPol    = 'User\registry.pol'
        secEditInf = 'secedit.inf'
        auditCsv   = 'Machine\Microsoft\Windows NT\Audit\audit.csv'
    }

    New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $exportDir 'Machine') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $exportDir 'User') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $exportDir 'Machine\Microsoft\Windows NT\Audit') -Force | Out-Null

    if ($isSavedProject) {
        $srcDir = $script:ActiveProject.Dir
        $srcFiles = $script:ActiveProject.Files
        Copy-GpoWorkingFile -CurrentPath (Join-Path $srcDir $srcFiles.machinePol) -Destination (Join-Path $exportDir $files.machinePol)
        Copy-GpoWorkingFile -CurrentPath (Join-Path $srcDir $srcFiles.userPol) -Destination (Join-Path $exportDir $files.userPol)
        Copy-GpoWorkingFile -CurrentPath (Join-Path $srcDir $srcFiles.secEditInf) -Destination (Join-Path $exportDir $files.secEditInf)
        Copy-GpoWorkingFile -CurrentPath (Join-Path $srcDir $srcFiles.auditCsv) -Destination (Join-Path $exportDir $files.auditCsv)
    }
    else {
        Copy-GpoWorkingFile -CurrentPath $script:MachinePolPath -Destination (Join-Path $exportDir $files.machinePol)
        Copy-GpoWorkingFile -CurrentPath $script:UserPolPath -Destination (Join-Path $exportDir $files.userPol)
        Copy-GpoWorkingFile -CurrentPath $script:SecEditInfPath -Destination (Join-Path $exportDir $files.secEditInf)
        Copy-GpoWorkingFile -CurrentPath $script:AuditCsvPath -Destination (Join-Path $exportDir $files.auditCsv)
    }

    Save-GpoProjectManifest -Path (Join-Path $exportDir "$($name)_Info.xml") -Name $name -Files $files
    Write-GpEditProjectLog -Action 'Exported' -ProjectName $name

    # Security Options changes outside any project are normally only
    # applied on window close - finalizing an Export also applies them
    # immediately here. SecurityOptionsDirty is never cleared, so the
    # close-time apply still runs too (accepted redundancy, idempotent).
    if (-not $script:ActiveProject -and $script:SecurityOptionsDirty) {
        if (-not (Test-IsRunningAsAdministrator)) {
            Show-AdminRequiredMessage -Ui $ui
        }
        else {
            try {
                $applyResult = Invoke-SecEditInfApply -SecEditInfPath $SecEditInfPath -RegistryValuesBaselineKeys $script:RegistryValuesBaselineKeys
                if ($applyResult.ExitCode -ne 0) {
                    Show-WriteErrorMessage -Ui $ui -ErrorText $applyResult.Output
                }
            }
            catch {
                Show-WriteErrorMessage -Ui $ui -ErrorText $_.Exception.Message
            }
        }
    }

    [System.Windows.MessageBox]::Show($ui.ExportSuccessMessage, $ui.InfoTitle, 'OK', 'Information') | Out-Null
}

function Set-CisProfileFilter {
    param($NewProfile)
    $script:CisProfileFilter = $NewProfile
    $script:CisActiveProfileForColumn = if ($NewProfile) { $NewProfile } else { $script:CisDefaultProfile }
    Update-ActiveProfileLabel
}

function Get-ActiveFilterCount {
    # Feeds the Filter menu badge (Ui.MenuFilterActiveFormat) - counts how
    # many of the independent filter dimensions are non-default.
    $count = 0
    if ($null -ne $script:CisProfileFilter) { $count++ }
    if ($script:FilterHasCisRecOnly) { $count++ }
    if ($script:FilterStateMode -ne 'Any') { $count++ }
    if (@($script:FilterScopes).Count -ne 2) { $count++ }
    if (@($script:FilterKinds).Count -ne 3) { $count++ }
    return $count
}

function Update-FilterMenuLabel {
    param([hashtable]$Ui)
    $activeCount = Get-ActiveFilterCount
    $filterMenu.Header = if ($activeCount -gt 0) { $Ui.MenuFilterActiveFormat -f $activeCount } else { $Ui.MenuFilter }
}

Update-FilterMenuLabel -Ui (Get-CurrentUi)

$filterMenu.Add_Click({
    param($EventSender, $e)
    $currentState = [pscustomobject]@{
        StateMode = $script:FilterStateMode
        Scopes = $script:FilterScopes
        Kinds = $script:FilterKinds
        Profile = $script:CisProfileFilter
        HasCisRecOnly = $script:FilterHasCisRecOnly
    }
    $ui = Get-CurrentUi
    $result = Show-FilterDialog -Owner $window -ScriptRoot $PSScriptRoot -Ui $ui -CisIndex $script:CisIndex -CurrentState $currentState
    if ($null -eq $result) { return }

    # State/Scope/Kind change which category folders even qualify as
    # "having policies" (Test-CategoryHasPolicies), so the tree itself -
    # not just the list - needs to be rebuilt for those three. CIS
    # profile/HasCisRecOnly instead just hide/show existing nodes (see
    # Update-TreeVisibilityForCisFilter) - cheaper, no rebuild needed.
    $treeDimensionsChanged = (
        $result.StateMode -ne $script:FilterStateMode -or
        (Compare-Object $result.Scopes $script:FilterScopes) -or
        (Compare-Object $result.Kinds $script:FilterKinds)
    )

    $script:FilterStateMode = $result.StateMode
    $script:FilterScopes = $result.Scopes
    $script:FilterKinds = $result.Kinds
    $script:FilterHasCisRecOnly = $result.HasCisRecOnly
    Set-CisProfileFilter -NewProfile $result.Profile
    Update-FilterMenuLabel -Ui $ui

    if ($treeDimensionsChanged) {
        $restoreInfo = Get-TreeSelectionRestoreInfo
        Rebuild-Tree -Ui $ui
        Restore-TreeSelection -Info $restoreInfo
    }
    # In search mode, Invoke-Search (called below by
    # Refresh-ListForCisStateChange) already recomputes tree filtering
    # combined with the active filters - don't overwrite with a version
    # that ignores the search text.
    if (-not $script:IsSearchActive) { Update-TreeVisibilityForCisFilter }
    Refresh-ListForCisStateChange
})

# --- Right-hand "Patch notes" pane ---------------------------------------
function Update-PatchNotesPanelContent {
    Set-ChangelogTextBlockContent -TextBlock $patchNotesTextBlock -Entries $script:ChangelogEntries -MaxEntries $script:PatchNotesEntryCount
}

function Switch-ToNormalView {
    # Switches permanently from "Patch notes" to the normal view on first
    # real navigation - never switches back while the app is running.
    if ($script:HasLeftInitialPatchNotesView) { return }
    $script:HasLeftInitialPatchNotesView = $true
    $patchNotesPanel.Visibility = 'Collapsed'
    $mainContentGrid.Visibility = 'Visible'
}

# --- File menu: Save / Exit -----------------------------------------------
$fileSaveMenuItem.Add_Click({
    param($EventSender, $e)
    if ($script:ActiveProject -and $script:ActiveProject.Saved) {
        # Project already saved/opened: doubles as "Save now".
        Invoke-SaveGpoProjectNow
    } else {
        # Not-yet-saved session: first save, via folder-browse flow.
        Save-GpoProjectAs
    }
})

$fileImportMenuItem.Add_Click({
    param($EventSender, $e)
    Import-GpoProjectFiles
})

$fileExportMenuItem.Add_Click({
    param($EventSender, $e)
    Export-GpoProjectFiles
})

$fileOptionsMenuItem.Add_Click({
    param($EventSender, $e)
    Show-OptionsDialog -Owner $window -ScriptRoot $PSScriptRoot -Ui (Get-CurrentUi)
})

$fileExitMenuItem.Add_Click({
    param($EventSender, $e)
    $window.Close()
})

# --- View > Add/remove columns --------------------------------------------
# Columns are removed from GridView.Columns then reinserted in the chosen
# order - Width=0 alone would hide a column but freeze its position,
# breaking the picker's Up/Down buttons. Category stays a member (hidden,
# width 0) even if not user-added, so search mode can still toggle it.
#
# A column gets its default width only the first time it's ever shown
# ($ColumnEverDisplayed); after that its width is left as the user set it.
# Name/State/CIS start shown from XAML, hence EverDisplayed=$true already.
$script:CurrentColumnOrder = @('Name', 'State', 'Cis')
$script:ColumnWidthByKey = @{ Name = 546; State = 165; Cis = 50; Scope = 90; RecommendedState = 160; Category = 260 }
$script:ColumnEverDisplayed = @{ Name = $true; State = $true; Cis = $true; Scope = $false; RecommendedState = $false; Category = $false }

function Get-ColumnByKeyMap {
    return @{
        Name              = $columnName
        State             = $columnState
        Cis               = $columnCis
        Scope             = $columnScope
        RecommendedState  = $columnRecommendedState
        Category          = $columnCategory
    }
}

function Sync-CurrentColumnOrderFromGridView {
    # Header drag-and-drop reorders policyList.View.Columns directly
    # without touching $script:CurrentColumnOrder. Resyncs the order here
    # before opening the picker, without touching membership.
    $keyByColumn = @{}
    foreach ($kv in (Get-ColumnByKeyMap).GetEnumerator()) { $keyByColumn[$kv.Value] = $kv.Key }
    $memberKeys = [System.Collections.Generic.HashSet[string]]::new([string[]]$script:CurrentColumnOrder)
    $newOrder = New-Object System.Collections.Generic.List[string]
    foreach ($col in $policyList.View.Columns) {
        if ($keyByColumn.ContainsKey($col)) {
            $key = $keyByColumn[$col]
            if ($memberKeys.Contains($key)) { $newOrder.Add($key) }
        }
    }
    $script:CurrentColumnOrder = $newOrder
}

function Set-ColumnsDisplay {
    param([string[]]$OrderedKeys)
    $script:CurrentColumnOrder = $OrderedKeys
    $columnByKey = Get-ColumnByKeyMap

    $columns = $policyList.View.Columns
    foreach ($col in $columnByKey.Values) { if ($columns.Contains($col)) { [void]$columns.Remove($col) } }

    $insertIndex = 0
    foreach ($key in $OrderedKeys) {
        if (-not $columnByKey.ContainsKey($key)) { continue }
        $col = $columnByKey[$key]
        if (-not $script:ColumnEverDisplayed[$key]) {
            $col.Width = $script:ColumnWidthByKey[$key]
            $script:ColumnEverDisplayed[$key] = $true
        }
        [void]$columns.Insert($insertIndex, $col)
        $insertIndex++
    }

    if ('Category' -notin $OrderedKeys) {
        [void]$columns.Add($columnCategory)
    }
}

# The Category column is toggled automatically by search (width 260 during,
# 0 outside) whether the user added it themselves via Add/remove columns or
# not; if it was added manually, its pre-search width/visibility is
# restored on exit instead of being hidden.
$script:CategoryColumnWidthBeforeSearch = $null

function Enter-SearchCategoryColumnMode {
    if ('Category' -in $script:CurrentColumnOrder) {
        $script:CategoryColumnWidthBeforeSearch = $columnCategory.Width
    }
    $columnCategory.Width = 260
}

function Exit-SearchCategoryColumnMode {
    if ('Category' -in $script:CurrentColumnOrder) {
        $columnCategory.Width = if ($null -ne $script:CategoryColumnWidthBeforeSearch) { $script:CategoryColumnWidthBeforeSearch } else { $script:ColumnWidthByKey['Category'] }
    }
    else {
        $columnCategory.Width = 0
    }
}

# --- "CIS States" column: reserved for Administrative Templates, shown by
# --- default only for an ADMX folder or during a global search.
# --- Repositioned at the end of the grid on every toggle since
# --- Set-ColumnsDisplay ignores it (absent from Get-ColumnByKeyMap).
$script:CisStatesColumnWidth = 260

function Set-CisStatesColumnVisible {
    param([bool]$Visible)

    $columnCisStates.Width = if ($Visible) { $script:CisStatesColumnWidth } else { 0 }

    $columns = $policyList.View.Columns
    if ($columns.Contains($columnCisStates)) { [void]$columns.Remove($columnCisStates) }
    [void]$columns.Add($columnCisStates)
}

$viewColumnsMenuItem.Add_Click({
    param($EventSender, $e)
    Sync-CurrentColumnOrderFromGridView
    $ui = Get-CurrentUi
    $result = Show-ColumnPickerDialog -Owner $window -ScriptRoot $PSScriptRoot -Ui $ui -DisplayedKeys $script:CurrentColumnOrder
    if ($null -ne $result) { Set-ColumnsDisplay -OrderedKeys $result }
})

# --- File menu: New/Open (off-machine GPO projects) -----------------------
# Import/Export intentionally have no handler: IsEnabled="False" permanently
# in the XAML - not wired up.
$fileNewMenuItem.Add_Click({ param($EventSender, $e) New-GpoProject })
$fileOpenMenuItem.Add_Click({ param($EventSender, $e) Open-GpoProject })

# --- Help menu (About / Patch note) ---------------------------------------
$helpAboutMenuItem.Add_Click({
    param($EventSender, $e)
    Show-AboutWindow -Owner $window -ScriptRoot $PSScriptRoot -Ui (Get-CurrentUi) -ChangelogEntries $script:ChangelogEntries
})
$helpPatchNoteMenuItem.Add_Click({
    param($EventSender, $e)
    Show-PatchNoteWindow -Owner $window -ScriptRoot $PSScriptRoot -Ui (Get-CurrentUi) -ChangelogEntries $script:ChangelogEntries
})
$helpLogsMenuItem.Add_Click({
    param($EventSender, $e)
    Open-GpEditLogFile
})

Update-StaticUiText -Ui (Get-CurrentUi)
Rebuild-Tree -Ui (Get-CurrentUi)
Update-ActiveProfileLabel

# --- State column width: wider by default in User Rights Assignment /
# Security Options (longer values). Applied once per menu per session,
# never again once a manual resize is detected via WidthProperty.
$script:StateColumnManuallyResized = $false
$script:StateColumnAutoApplying = $false
$script:StateColumnVisitedMenus = New-Object 'System.Collections.Generic.HashSet[string]'
$script:StateWideSecurityCategories = @('User Rights Assignment', 'Security Options')

$stateWidthPropertyDescriptor = [System.ComponentModel.DependencyPropertyDescriptor]::FromProperty(
    [System.Windows.Controls.GridViewColumn]::WidthProperty, [System.Windows.Controls.GridViewColumn])
$stateWidthPropertyDescriptor.AddValueChanged($columnState, {
    if (-not $script:StateColumnAutoApplying) { $script:StateColumnManuallyResized = $true }
})

function Update-StateColumnWidthForMenu {
    param([string]$MenuId, [bool]$IsWide)
    if ($script:StateColumnManuallyResized) { return }
    if ($script:StateColumnVisitedMenus.Contains($MenuId)) { return }
    [void]$script:StateColumnVisitedMenus.Add($MenuId)
    $script:StateColumnAutoApplying = $true
    try { $columnState.Width = if ($IsWide) { 195 } else { 165 } }
    finally { $script:StateColumnAutoApplying = $false }
}

function Invoke-UiRenderPass {
    # Forces WPF to process pending render/layout before a blocking
    # synchronous operation - otherwise the display only updates after the
    # operation finishes, too late to act as a loading indicator.
    $window.Dispatcher.Invoke([action]{}, [System.Windows.Threading.DispatcherPriority]::Render) | Out-Null
}

# --- Populating the list from the selected category -----------------------
function Update-PolicyList {
    $selected = $categoryTree.SelectedItem
    if ($null -eq $selected) { return }
    $tag = $selected.Tag
    $ui = Get-CurrentUi

    # Preserves the selected row: ItemsSource is fully rebuilt below (new
    # object list), which would otherwise lose selection on OK (Cancel
    # doesn't call this function, so it naturally keeps selection).
    $previousSelected = $policyList.SelectedItem
    $previousSelectedPolicyId = $null
    $previousSelectedKind = $null
    $previousSelectedScope = $null
    if ($previousSelected) {
        $previousSelectedPolicyId = $previousSelected.PolicyId
        $previousSelectedKind = $previousSelected.Kind
        $previousSelectedScope = $previousSelected.Scope
    }

    # Selecting a tree node always exits search mode and hides the Category
    # column, which is only useful when the list mixes several categories.
    $wasSearching = $script:IsSearchActive
    $script:IsSearchActive = $false
    Exit-SearchCategoryColumnMode
    if ($wasSearching) { Show-AllTreeItems }

    $items = New-Object System.Collections.Generic.List[object]

    if ($tag.Kind -eq 'AdmxCategory') {
        Update-StateColumnWidthForMenu -MenuId "Admx|$($tag.CategoryId)|$($tag.Scope)" -IsWide $false
        $cat = $script:categoriesById[$tag.CategoryId]
        $categoryPathLabel.Text = $cat.pathText
        $lookup = if ($tag.Scope -eq 'Machine') { $machineLookup } else { $userLookup }
        if ($script:policiesByCategory.ContainsKey($tag.CategoryId)) {
            foreach ($pol in $script:policiesByCategory[$tag.CategoryId]) {
                if (-not (Test-PolicyMatchesScope -PolicyClass $pol.class -Scope $tag.Scope)) { continue }
                $state = Get-AdmxPolicyState -Policy $pol -PolLookup $lookup
                $cisRec = Get-CisRecommendationForRegistry -CisIndex $script:CisIndex -RegistryKey $pol.registryKey -ValueName $pol.valueName
                if (-not (Test-CisProfileFilterMatch -CisEntry $cisRec)) { continue }
                $cisRowLabels = Get-CisRowLabels -CisEntry $cisRec -Ui $ui
                $items.Add([pscustomobject]@{
                    DisplayName = $pol.displayName
                    StateLabel  = Get-AdmxPolicyStateLabel -State $state -Ui $ui
                    ScopeLabel  = if ($tag.Scope -eq 'Machine') { $ui.ScopeComputer } else { $ui.ScopeUser }
                    CisLabel    = $cisRowLabels.CisLabel
                    RecommendedStateLabel = $cisRowLabels.RecommendedStateLabel
                    CisStatesLabel = $cisRowLabels.CisStatesLabel
                    PolicyId    = $pol.id
                    IconGlyph   = $script:IconGlyphAdmxSetting
                    Kind        = 'Admx'
                    Scope       = $tag.Scope
                    IsConfigured = ($state -ne 'NotConfigured')
                })
            }
        }
        $items = [System.Collections.Generic.List[object]]@($items | Sort-Object DisplayName)
        Set-CisStatesColumnVisible -Visible $true
    }
    elseif ($tag.Kind -eq 'SecurityCategory') {
        Update-StateColumnWidthForMenu -MenuId "Security|$($tag.SecurityCategory)" -IsWide ($tag.SecurityCategory -in $script:StateWideSecurityCategories)
        $categoryPathLabel.Text = ($ui.SecurityBreadcrumbPrefix -f $tag.Label)
        foreach ($setting in $script:securityIndex.settings) {
            if ($setting.category -ne $tag.SecurityCategory) { continue }
            $cisRec = Get-CisRecommendationForSecuritySetting -CisIndex $script:CisIndex -Section $setting.section -Name $setting.name
            if (-not (Test-CisProfileFilterMatch -CisEntry $cisRec)) { continue }
            $cisRowLabels = Get-CisRowLabels -CisEntry $cisRec -Ui $ui
            $items.Add([pscustomobject]@{
                DisplayName = $setting.displayName
                StateLabel  = Format-SecuritySettingValue -Setting $setting -Ui $ui
                ScopeLabel  = $ui.ScopeComputer
                CisLabel    = $cisRowLabels.CisLabel
                RecommendedStateLabel = $cisRowLabels.RecommendedStateLabel
                CisStatesLabel = $cisRowLabels.CisStatesLabel
                PolicyId    = $setting.id
                IconGlyph   = $script:IconGlyphSecuritySetting
                Kind        = 'Security'
                Scope       = $null
                IsConfigured = $setting.isConfigured
            })
        }
        $items = [System.Collections.Generic.List[object]]@($items | Sort-Object DisplayName)
        Set-CisStatesColumnVisible -Visible $false
    }
    elseif ($tag.Kind -eq 'AdvancedAuditCategory') {
        Update-StateColumnWidthForMenu -MenuId "AdvAudit|$($tag.AdvAuditCategory)" -IsWide $false
        $categoryPathLabel.Text = "$($ui.AdvancedAuditPolicyConfig) > $($ui.AdvancedAuditPolicyObject) > $($tag.Label)"
        foreach ($setting in $script:advancedAuditIndex.settings) {
            if ($setting.category -ne $tag.AdvAuditCategory) { continue }
            $cisRec = Get-CisRecommendationForAuditSubcategory -CisIndex $script:CisIndex -SubcategoryNameEn $setting.name
            if (-not (Test-CisProfileFilterMatch -CisEntry $cisRec)) { continue }
            $cisRowLabels = Get-CisRowLabels -CisEntry $cisRec -Ui $ui
            $items.Add([pscustomobject]@{
                DisplayName = $setting.displayName
                StateLabel  = Format-SecuritySettingValue -Setting $setting -Ui $ui
                ScopeLabel  = $ui.ScopeComputer
                CisLabel    = $cisRowLabels.CisLabel
                RecommendedStateLabel = $cisRowLabels.RecommendedStateLabel
                CisStatesLabel = $cisRowLabels.CisStatesLabel
                PolicyId    = $setting.id
                IconGlyph   = $script:IconGlyphAuditSetting
                Kind        = 'AdvancedAudit'
                Scope       = $null
                IsConfigured = $setting.isConfigured
            })
        }
        $items = [System.Collections.Generic.List[object]]@($items | Sort-Object DisplayName)
        Set-CisStatesColumnVisible -Visible $false
    }
    elseif ($tag.Kind -eq 'Group' -and $tag.GroupId -eq 'Overview') {
        # GroupId (not Kind) is what distinguishes "Overview" from other
        # container folders. Aggregates every setting, subject to the
        # active CIS profile filter. Category column shown since the list
        # mixes several categories.
        Update-StateColumnWidthForMenu -MenuId 'Overview' -IsWide $false
        Enter-SearchCategoryColumnMode
        $categoryPathLabel.Text = $ui.Overview

        # Loading indicator: this view aggregates thousands of settings and
        # takes several seconds. Invoke-UiRenderPass forces the display to
        # update before the blocking loops, otherwise the hourglass and the
        # computation finish together, making it invisible. try/finally so
        # it's never left stuck if a loop throws.
        $script:OverviewLoadingIcon.Visibility = 'Visible'
        Invoke-UiRenderPass
        try {

        foreach ($pol in $script:admxIndex.policies) {
            foreach ($scope in @('Machine', 'User')) {
                if (-not (Test-PolicyMatchesScope -PolicyClass $pol.class -Scope $scope)) { continue }
                $lookup = if ($scope -eq 'Machine') { $machineLookup } else { $userLookup }
                $state = Get-AdmxPolicyState -Policy $pol -PolLookup $lookup
                $cisRec = Get-CisRecommendationForRegistry -CisIndex $script:CisIndex -RegistryKey $pol.registryKey -ValueName $pol.valueName
                if (-not (Test-CisProfileFilterMatch -CisEntry $cisRec)) { continue }
                $cisRowLabels = Get-CisRowLabels -CisEntry $cisRec -Ui $ui
                $items.Add([pscustomobject]@{
                    DisplayName   = $pol.displayName
                    StateLabel    = Get-AdmxPolicyStateLabel -State $state -Ui $ui
                    ScopeLabel    = if ($scope -eq 'Machine') { $ui.ScopeComputer } else { $ui.ScopeUser }
                    CategoryLabel = $pol.categoryPathText
                    CisLabel      = $cisRowLabels.CisLabel
                    RecommendedStateLabel = $cisRowLabels.RecommendedStateLabel
                    CisStatesLabel = $cisRowLabels.CisStatesLabel
                    PolicyId      = $pol.id
                    IconGlyph     = $script:IconGlyphAdmxSetting
                    Kind          = 'Admx'
                    Scope         = $scope
                    IsConfigured  = ($state -ne 'NotConfigured')
                })
            }
        }

        foreach ($setting in $script:securityIndex.settings) {
            $catKey = $script:SecurityCategoryToUiKey[$setting.category]
            $catLabel = if ($catKey) { $ui[$catKey] } else { $setting.category }
            $cisRec = Get-CisRecommendationForSecuritySetting -CisIndex $script:CisIndex -Section $setting.section -Name $setting.name
            if (-not (Test-CisProfileFilterMatch -CisEntry $cisRec)) { continue }
            $cisRowLabels = Get-CisRowLabels -CisEntry $cisRec -Ui $ui
            $items.Add([pscustomobject]@{
                DisplayName   = $setting.displayName
                StateLabel    = Format-SecuritySettingValue -Setting $setting -Ui $ui
                ScopeLabel    = $ui.ScopeComputer
                CategoryLabel = "$($ui.WindowsSettings) > $($ui.SecuritySettings) > $catLabel"
                CisLabel      = $cisRowLabels.CisLabel
                RecommendedStateLabel = $cisRowLabels.RecommendedStateLabel
                CisStatesLabel = $cisRowLabels.CisStatesLabel
                PolicyId      = $setting.id
                IconGlyph     = $script:IconGlyphSecuritySetting
                Kind          = 'Security'
                Scope         = $null
                IsConfigured  = $setting.isConfigured
            })
        }

        foreach ($setting in $script:advancedAuditIndex.settings) {
            $catLabel = $ui["AdvAudit$($setting.category)"]
            $cisRec = Get-CisRecommendationForAuditSubcategory -CisIndex $script:CisIndex -SubcategoryNameEn $setting.name
            if (-not (Test-CisProfileFilterMatch -CisEntry $cisRec)) { continue }
            $cisRowLabels = Get-CisRowLabels -CisEntry $cisRec -Ui $ui
            $items.Add([pscustomobject]@{
                DisplayName   = $setting.displayName
                StateLabel    = Format-SecuritySettingValue -Setting $setting -Ui $ui
                ScopeLabel    = $ui.ScopeComputer
                CategoryLabel = "$($ui.AdvancedAuditPolicyConfig) > $($ui.AdvancedAuditPolicyObject) > $catLabel"
                CisLabel      = $cisRowLabels.CisLabel
                RecommendedStateLabel = $cisRowLabels.RecommendedStateLabel
                CisStatesLabel = $cisRowLabels.CisStatesLabel
                PolicyId      = $setting.id
                IconGlyph     = $script:IconGlyphAuditSetting
                Kind          = 'AdvancedAudit'
                Scope         = $null
                IsConfigured  = $setting.isConfigured
            })
        }

        # Sorted by Category, not Name: grouping by location is more
        # readable when mixing every category.
        $items = [System.Collections.Generic.List[object]]@($items | Sort-Object CategoryLabel, DisplayName)
        }
        finally {
            $script:OverviewLoadingIcon.Visibility = 'Collapsed'
        }
        Set-CisStatesColumnVisible -Visible $true
    }
    else {
        $categoryPathLabel.Text = $tag.Label
        Set-CisStatesColumnVisible -Visible $false
    }

    $items = Select-FilteredItems -Items $items
    $policyList.ItemsSource = $items
    $statusLabel.Text = ($ui.StatusItemsDisplayed -f $items.Count)

    if ($previousSelectedPolicyId) {
        $toReselect = $items | Where-Object {
            $_.PolicyId -eq $previousSelectedPolicyId -and
            $_.Kind -eq $previousSelectedKind -and
            $_.Scope -eq $previousSelectedScope
        } | Select-Object -First 1
        if ($toReselect) {
            $policyList.SelectedItem = $toReselect
            $policyList.ScrollIntoView($toReselect)
        }
    }
}

$categoryTree.Add_SelectedItemChanged({
    param($EventSender, $e)
    Switch-ToNormalView
    if ($script:IsSearchActive) {
        Update-SearchResultsForSelectedCategory
    }
    else {
        Update-PolicyList
    }
})

# --- "Technical details" panel: registry key / ADMX file for the setting
# --- selected in the list (without opening the edit dialog). -------------
function Update-DetailPanel {
    $ui = Get-CurrentUi
    $selectedItem = $policyList.SelectedItem
    if ($null -eq $selectedItem) {
        $detailTextBox.Text = $ui.DetailNoSelection
        return
    }

    if ($selectedItem.Kind -eq 'Admx') {
        $pol = $script:admxIndex.policies | Where-Object { $_.id -eq $selectedItem.PolicyId } | Select-Object -First 1
        if ($pol) { $detailTextBox.Text = Get-AdmxTechnicalDetailText -Policy $pol -Scope $selectedItem.Scope -Ui $ui }
    }
    elseif ($selectedItem.Kind -eq 'Security') {
        $setting = $script:securityIndex.settings | Where-Object { $_.id -eq $selectedItem.PolicyId } | Select-Object -First 1
        if ($setting) { $detailTextBox.Text = Get-SecurityTechnicalDetailText -Setting $setting -Ui $ui }
    }
    elseif ($selectedItem.Kind -eq 'AdvancedAudit') {
        $setting = $script:advancedAuditIndex.settings | Where-Object { $_.id -eq $selectedItem.PolicyId } | Select-Object -First 1
        if ($setting) { $detailTextBox.Text = Get-AdvancedAuditTechnicalDetailText -Setting $setting -Ui $ui }
    }
}

$policyList.Add_SelectionChanged({
    param($EventSender, $e)
    Update-DetailPanel
})

# ---------------------------------------------------------------------------
# Global search (name + explanation), across ADMX policies and security
# settings. Filters live while typing; double-click/Enter on a result
# navigates to the matching tree node then opens the edit dialog directly.
# ---------------------------------------------------------------------------

function Test-ContainsIgnoreCase {
    # Equivalent to -like "*$Needle*" without wildcard chars being
    # interpreted if the user types "*", "[" etc.
    param([string]$Haystack, [string]$Needle)
    if ([string]::IsNullOrEmpty($Haystack) -or [string]::IsNullOrEmpty($Needle)) { return $false }
    return $Haystack.IndexOf($Needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
}

$script:SecurityCategoryToUiKey = @{
    'Password Policy'         = 'PasswordPolicy'
    'Account Lockout Policy'  = 'AccountLockoutPolicy'
    'Audit Policy'            = 'AuditPolicy'
    'User Rights Assignment'  = 'UserRightsAssignment'
    'Security Options'        = 'SecurityOptions'
}

function Add-TreeKeepVisible {
    # Marks a node and its ancestor chain (precomputed at tree build) as
    # needing to stay visible/expanded while the tree is filtered.
    param([hashtable]$KeepSet, $Node, [object[]]$Ancestors)
    if (-not $Node) { return }
    $KeepSet[$Node] = $true
    foreach ($a in $Ancestors) {
        $KeepSet[$a] = $true
        $a.IsExpanded = $true
    }
}

function Update-TreeVisibilityForSearch {
    # Shows only categories (and ancestors) containing at least one result.
    param([hashtable]$KeepSet)
    foreach ($tvi in $script:AllTreeItems) {
        $tvi.Visibility = if ($KeepSet.ContainsKey($tvi)) { 'Visible' } else { 'Collapsed' }
    }
    # "Overview" is never "the category" or an ancestor of any setting, so
    # Add-TreeKeepVisible never marks it - without this explicit guard it
    # would disappear under any active filter, becoming unreselectable.
    if ($script:TreeItemsByGroupId.ContainsKey('Overview')) {
        $script:TreeItemsByGroupId['Overview'].Visibility = 'Visible'
    }
}

function Show-AllTreeItems {
    # Restores normal visibility for every node, collapsed (fresh state,
    # like startup). Called only when actually leaving search mode.
    foreach ($tvi in $script:AllTreeItems) {
        $tvi.Visibility = 'Visible'
        $tvi.IsExpanded = $false
    }
}

function Get-SelectedSearchField {
    # Order of the ComboBoxItems in SearchFieldCombo (AllWindows.Reference.xaml):
    # 0=Any, 1=Name, 2=Description, 3=Key, 4=CIS Number.
    switch ($searchFieldCombo.SelectedIndex) {
        1 { return 'Name' }
        2 { return 'Description' }
        3 { return 'Key' }
        4 { return 'CisNumber' }
        default { return 'Any' }
    }
}

function Test-SearchCisNumberMatch {
    # Searches the CIS number (e.g. "18.9.51.1.1") of every profile in
    # $CisEntry - used by both "Any" mode and the dedicated "CIS Number" mode.
    param([string]$Query, $CisEntry)
    if (-not $CisEntry) { return $false }
    foreach ($p in @($CisEntry.profiles)) {
        if (Test-ContainsIgnoreCase $p.cisNumber $Query) { return $true }
    }
    return $false
}

function Test-AdmxKeyMatch {
    # "Key" field: same fields as the "Technical details" panel - ADMX
    # file, registry key, value name, plus each element's id/value/key.
    param([string]$Query, $Policy)
    if (Test-ContainsIgnoreCase $Policy.registryKey $Query) { return $true }
    if (Test-ContainsIgnoreCase $Policy.valueName $Query) { return $true }
    if (Test-ContainsIgnoreCase $Policy.admxFile $Query) { return $true }
    foreach ($el in @($Policy.elements)) {
        if ((Test-ContainsIgnoreCase $el.id $Query) -or (Test-ContainsIgnoreCase $el.valueName $Query) -or (Test-ContainsIgnoreCase $el.key $Query)) { return $true }
    }
    return $false
}

function Test-SearchMatchAdmx {
    param([string]$Field, [string]$Query, $Policy, $CisEntry)
    switch ($Field) {
        'Name'        { return Test-ContainsIgnoreCase $Policy.displayName $Query }
        # An ADMX policy has no "Description" distinct from its
        # explanation; explainText is the only descriptive field.
        'Description' { return Test-ContainsIgnoreCase $Policy.explainText $Query }
        'Key'         { return Test-AdmxKeyMatch -Query $Query -Policy $Policy }
        'CisNumber'   { return Test-SearchCisNumberMatch -Query $Query -CisEntry $CisEntry }
        default {
            return (Test-ContainsIgnoreCase $Policy.displayName $Query) -or (Test-ContainsIgnoreCase $Policy.explainText $Query) `
                -or (Test-AdmxKeyMatch -Query $Query -Policy $Policy) -or (Test-SearchCisNumberMatch -Query $Query -CisEntry $CisEntry)
        }
    }
}

function Test-SearchMatchSecurity {
    param([string]$Field, [string]$Query, $Setting, $CisEntry)
    switch ($Field) {
        'Name'        { return Test-ContainsIgnoreCase $Setting.displayName $Query }
        'Description' { return Test-ContainsIgnoreCase $Setting.description $Query }
        'Key'         { return (Test-ContainsIgnoreCase $Setting.name $Query) -or (Test-ContainsIgnoreCase $Setting.section $Query) }
        'CisNumber'   { return Test-SearchCisNumberMatch -Query $Query -CisEntry $CisEntry }
        default {
            return (Test-ContainsIgnoreCase $Setting.displayName $Query) -or (Test-ContainsIgnoreCase $Setting.description $Query) `
                -or (Test-ContainsIgnoreCase $Setting.name $Query) -or (Test-ContainsIgnoreCase $Setting.section $Query) `
                -or (Test-SearchCisNumberMatch -Query $Query -CisEntry $CisEntry)
        }
    }
}

function Test-SearchMatchAdvancedAudit {
    param([string]$Field, [string]$Query, $Setting, $CisEntry)
    switch ($Field) {
        'Name'        { return Test-ContainsIgnoreCase $Setting.displayName $Query }
        # AdvancedAuditCatalog.ps1 always leaves "description" empty - this
        # mode legitimately never returns a result here.
        'Description' { return Test-ContainsIgnoreCase $Setting.description $Query }
        'Key'         { return (Test-ContainsIgnoreCase $Setting.name $Query) -or (Test-ContainsIgnoreCase $Setting.guid $Query) }
        'CisNumber'   { return Test-SearchCisNumberMatch -Query $Query -CisEntry $CisEntry }
        default {
            return (Test-ContainsIgnoreCase $Setting.displayName $Query) -or (Test-ContainsIgnoreCase $Setting.name $Query) `
                -or (Test-ContainsIgnoreCase $Setting.guid $Query) -or (Test-SearchCisNumberMatch -Query $Query -CisEntry $CisEntry)
        }
    }
}

function Invoke-Search {
    param(
        [string]$Query,
        # A new search always starts unrestricted. Only the programmatic
        # restore call keeps $script:SearchScopedNode as-is.
        [switch]$PreserveScope
    )
    Switch-ToNormalView
    $ui = Get-CurrentUi
    if (-not $PreserveScope) { $script:SearchScopedNode = $null }
    $script:IsSearchActive = $true
    $script:LastSearchQuery = $Query
    Enter-SearchCategoryColumnMode
    Set-CisStatesColumnVisible -Visible $true
    $keepVisible = @{}

    $items = New-Object System.Collections.Generic.List[object]
    $searchField = Get-SelectedSearchField

    foreach ($pol in $script:admxIndex.policies) {
        # Computes the CIS recommendation first (does not depend on scope):
        # needed before the match filter since "Any" mode also searches the
        # CIS number - reused inside the scope loop below.
        $cisRec = Get-CisRecommendationForRegistry -CisIndex $script:CisIndex -RegistryKey $pol.registryKey -ValueName $pol.valueName
        if (-not (Test-SearchMatchAdmx -Field $searchField -Query $Query -Policy $pol -CisEntry $cisRec)) { continue }
        if (-not (Test-KindFilterMatch -Kind 'Admx')) { continue }
        foreach ($scope in @('Machine', 'User')) {
            if (-not (Test-PolicyMatchesScope -PolicyClass $pol.class -Scope $scope)) { continue }
            if (-not (Test-ScopeFilterMatch -Scope $scope)) { continue }
            $lookup = if ($scope -eq 'Machine') { $machineLookup } else { $userLookup }
            $state = Get-AdmxPolicyState -Policy $pol -PolLookup $lookup
            $treeKey = "$($pol.categoryId)|$scope"
            $treeNode = if ($script:TreeItemsByAdmxCategoryScope.ContainsKey($treeKey)) { $script:TreeItemsByAdmxCategoryScope[$treeKey] } else { $null }
            if (-not (Test-CisProfileFilterMatch -CisEntry $cisRec)) { continue }
            if (-not (Test-StateFilterMatch -AdmxState $state -IsConfigured ($state -ne 'NotConfigured'))) { continue }
            $cisRowLabels = Get-CisRowLabels -CisEntry $cisRec -Ui $ui
            $items.Add([pscustomobject]@{
                DisplayName   = $pol.displayName
                StateLabel    = Get-AdmxPolicyStateLabel -State $state -Ui $ui
                ScopeLabel    = if ($scope -eq 'Machine') { $ui.ScopeComputer } else { $ui.ScopeUser }
                CategoryLabel = $pol.categoryPathText
                CisLabel      = $cisRowLabels.CisLabel
                RecommendedStateLabel = $cisRowLabels.RecommendedStateLabel
                CisStatesLabel = $cisRowLabels.CisStatesLabel
                PolicyId      = $pol.id
                IconGlyph     = $script:IconGlyphAdmxSetting
                Kind          = 'Admx'
                Scope         = $scope
                TreeNode      = $treeNode
                IsConfigured  = ($state -ne 'NotConfigured')
            })
            if ($treeNode) {
                Add-TreeKeepVisible -KeepSet $keepVisible -Node $treeNode -Ancestors $script:TreeAncestorsByKey[$treeKey]
            }
        }
    }

    if ((Test-KindFilterMatch -Kind 'Security') -and (Test-ScopeFilterMatch -Scope $null)) {
        foreach ($setting in $script:securityIndex.settings) {
            $cisRec = Get-CisRecommendationForSecuritySetting -CisIndex $script:CisIndex -Section $setting.section -Name $setting.name
            if (-not (Test-SearchMatchSecurity -Field $searchField -Query $Query -Setting $setting -CisEntry $cisRec)) { continue }
            $catKey = $script:SecurityCategoryToUiKey[$setting.category]
            $catLabel = if ($catKey) { $ui[$catKey] } else { $setting.category }
            $treeNode = if ($script:TreeItemsBySecurityCategory.ContainsKey($setting.category)) { $script:TreeItemsBySecurityCategory[$setting.category] } else { $null }
            if (-not (Test-CisProfileFilterMatch -CisEntry $cisRec)) { continue }
            if (-not (Test-StateFilterMatch -AdmxState $null -IsConfigured $setting.isConfigured)) { continue }
            $cisRowLabels = Get-CisRowLabels -CisEntry $cisRec -Ui $ui
            $items.Add([pscustomobject]@{
                DisplayName   = $setting.displayName
                StateLabel    = Format-SecuritySettingValue -Setting $setting -Ui $ui
                ScopeLabel    = $ui.ScopeComputer
                CategoryLabel = "$($ui.WindowsSettings) > $($ui.SecuritySettings) > $catLabel"
                CisLabel      = $cisRowLabels.CisLabel
                RecommendedStateLabel = $cisRowLabels.RecommendedStateLabel
                CisStatesLabel = $cisRowLabels.CisStatesLabel
                PolicyId      = $setting.id
                IconGlyph     = $script:IconGlyphSecuritySetting
                Kind          = 'Security'
                Scope         = $null
                TreeNode      = $treeNode
                IsConfigured  = $setting.isConfigured
            })
            if ($treeNode) {
                Add-TreeKeepVisible -KeepSet $keepVisible -Node $treeNode -Ancestors $script:TreeAncestorsBySecurityCategory[$setting.category]
            }
        }
    }

    if ((Test-KindFilterMatch -Kind 'AdvancedAudit') -and (Test-ScopeFilterMatch -Scope $null)) {
        foreach ($setting in $script:advancedAuditIndex.settings) {
            $cisRec = Get-CisRecommendationForAuditSubcategory -CisIndex $script:CisIndex -SubcategoryNameEn $setting.name
            if (-not (Test-SearchMatchAdvancedAudit -Field $searchField -Query $Query -Setting $setting -CisEntry $cisRec)) { continue }
            $catLabel = $ui["AdvAudit$($setting.category)"]
            $treeNode = if ($script:TreeItemsByAdvAuditCategory.ContainsKey($setting.category)) { $script:TreeItemsByAdvAuditCategory[$setting.category] } else { $null }
            if (-not (Test-CisProfileFilterMatch -CisEntry $cisRec)) { continue }
            if (-not (Test-StateFilterMatch -AdmxState $null -IsConfigured $setting.isConfigured)) { continue }
            $cisRowLabels = Get-CisRowLabels -CisEntry $cisRec -Ui $ui
            $items.Add([pscustomobject]@{
                DisplayName   = $setting.displayName
                StateLabel    = Format-SecuritySettingValue -Setting $setting -Ui $ui
                ScopeLabel    = $ui.ScopeComputer
                CategoryLabel = "$($ui.AdvancedAuditPolicyConfig) > $($ui.AdvancedAuditPolicyObject) > $catLabel"
                CisLabel      = $cisRowLabels.CisLabel
                RecommendedStateLabel = $cisRowLabels.RecommendedStateLabel
                CisStatesLabel = $cisRowLabels.CisStatesLabel
                PolicyId      = $setting.id
                IconGlyph     = $script:IconGlyphAuditSetting
                Kind          = 'AdvancedAudit'
                Scope         = $null
                TreeNode      = $treeNode
                IsConfigured  = $setting.isConfigured
            })
            if ($treeNode) {
                Add-TreeKeepVisible -KeepSet $keepVisible -Node $treeNode -Ancestors $script:TreeAncestorsByAdvAuditCategory[$setting.category]
            }
        }
    }

    $items = [System.Collections.Generic.List[object]]@($items | Sort-Object DisplayName)
    # Filter menu state already applied per-item above (Kind/Scope/State)
    # and via Test-CisProfileFilterMatch (profile/HasCisRecOnly) - nothing
    # left to reapply here, unlike the tree-click path where
    # Select-FilteredItems runs after Update-PolicyList builds $items.
    $script:SearchResultItems = $items
    $policyList.ItemsSource = $items
    $categoryPathLabel.Text = ($ui.SearchResultsHeaderFormat -f $Query, $items.Count)
    $statusLabel.Text = if ($items.Count -eq 0) { $ui.SearchNoResults } else { ($ui.StatusItemsDisplayed -f $items.Count) }
    Update-TreeVisibilityForSearch -KeepSet $keepVisible
}

function Get-DescendantTreeViewItemSet {
    # Returns the node and all its descendants. Tree is built by hand (no
    # HierarchicalDataTemplate), so a plain stack traversal is enough.
    param($Node)
    $set = @{}
    $stack = New-Object System.Collections.Generic.Stack[object]
    $stack.Push($Node)
    while ($stack.Count -gt 0) {
        $current = $stack.Pop()
        $set[$current] = $true
        foreach ($child in $current.Items) { $stack.Push($child) }
    }
    return $set
}

function Get-TreeNodeLabel {
    # AdmxCategory only stores CategoryId; its label lives in
    # $script:categoriesById.
    param($Tvi)
    if ($Tvi.Tag.Kind -eq 'AdmxCategory') { return $script:categoriesById[$Tvi.Tag.CategoryId].displayName }
    return $Tvi.Tag.Label
}

function Update-SearchResultsForSelectedCategory {
    # During search, clicking a tree folder no longer exits search mode:
    # the list is restricted to that folder and its children. Clicking a
    # root goes back to the full result set.
    $ui = Get-CurrentUi
    $selected = $categoryTree.SelectedItem
    if ($null -eq $selected -or $null -eq $script:SearchResultItems) { return }

    if ($categoryTree.Items.Contains($selected)) {
        # Root (Computer/User Configuration): no more folder restriction,
        # the full result set becomes the scope again.
        $script:SearchScopedNode = $null
        $filtered = $script:SearchResultItems
        $categoryPathLabel.Text = ($ui.SearchResultsHeaderFormat -f $script:LastSearchQuery, $filtered.Count)
    }
    else {
        $script:SearchScopedNode = $selected
        $descendantSet = Get-DescendantTreeViewItemSet -Node $selected
        $filtered = [System.Collections.Generic.List[object]]@($script:SearchResultItems | Where-Object { $_.TreeNode -and $descendantSet.ContainsKey($_.TreeNode) })
        $categoryPathLabel.Text = ($ui.SearchResultsInCategoryFormat -f $script:LastSearchQuery, (Get-TreeNodeLabel -Tvi $selected), $filtered.Count)
    }

    $policyList.ItemsSource = $filtered
    $statusLabel.Text = if ($filtered.Count -eq 0) { $ui.SearchNoResults } else { ($ui.StatusItemsDisplayed -f $filtered.Count) }
}

function Reset-ToCategoryOrPrompt {
    # Resets the list to normal content without touching the search box
    # text - used by TextChanged when the box becomes empty, since
    # GotFocus would otherwise immediately restore the placeholder.
    $ui = Get-CurrentUi
    $wasSearching = $script:IsSearchActive
    $script:IsSearchActive = $false
    Exit-SearchCategoryColumnMode
    if ($wasSearching) { Show-AllTreeItems }
    if ($categoryTree.SelectedItem) {
        Update-PolicyList
    }
    else {
        $policyList.ItemsSource = $null
        $categoryPathLabel.Text = $ui.SelectCategoryPrompt
        $statusLabel.Text = ($ui.StatusIndexSummary -f $admxIndex.policies.Count, $admxIndex.categories.Count, $securityIndex.settings.Count)
    }
}

function Clear-Search {
    # Fully clears the search. Used by "Clear" and LostFocus - never by
    # TextChanged (see Reset-ToCategoryOrPrompt).
    $searchBox.Text = (Get-CurrentUi).SearchPlaceholder
    $searchBox.Foreground = 'Gray'
    Reset-ToCategoryOrPrompt
}

$searchBox.Add_GotFocus({
    param($EventSender, $e)
    $ui = Get-CurrentUi
    if ($searchBox.Text -eq $ui.SearchPlaceholder) {
        $searchBox.Text = ''
        $searchBox.Foreground = 'Black'
    }
})

$searchBox.Add_LostFocus({
    param($EventSender, $e)
    if ([string]::IsNullOrWhiteSpace($searchBox.Text)) {
        $searchBox.Text = (Get-CurrentUi).SearchPlaceholder
        $searchBox.Foreground = 'Gray'
    }
})

$script:MinSearchLength = 2

# Invoke-Search scans ~3300 policies: too costly per keystroke (the
# TextChanged handler is synchronous on the UI thread). Debounced via a
# DispatcherTimer: each keystroke restarts the delay, only the last one
# of a burst triggers the search.
$script:SearchDebounceTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:SearchDebounceTimer.Interval = [TimeSpan]::FromMilliseconds(180)
$script:SearchDebounceTimer.Add_Tick({
    param($EventSender, $e)
    $script:SearchDebounceTimer.Stop()
    $ui = Get-CurrentUi
    $text = $searchBox.Text
    if ($text -eq $ui.SearchPlaceholder) { return }
    if ($text.Trim().Length -lt $script:MinSearchLength) { Reset-ToCategoryOrPrompt; return }
    Invoke-Search -Query $text
})

$searchBox.Add_TextChanged({
    param($EventSender, $e)
    $ui = Get-CurrentUi
    $text = $searchBox.Text
    $script:SearchDebounceTimer.Stop()
    if ($text -eq $ui.SearchPlaceholder) { return }
    if ($text.Trim().Length -lt $script:MinSearchLength) { Reset-ToCategoryOrPrompt; return }
    $script:SearchDebounceTimer.Start()
})

$searchButton.Add_Click({
    param($EventSender, $e)
    $ui = Get-CurrentUi
    $text = $searchBox.Text
    if ($text -ne $ui.SearchPlaceholder -and $text.Trim().Length -ge $script:MinSearchLength) {
        Invoke-Search -Query $text
    }
})

$searchFieldCombo.Add_SelectionChanged({
    param($EventSender, $e)
    $ui = Get-CurrentUi
    $text = $searchBox.Text
    if ($text -eq $ui.SearchPlaceholder) { return }
    if ($text.Trim().Length -lt $script:MinSearchLength) { return }
    Invoke-Search -Query $text
})

$clearSearchButton.Add_Click({
    param($EventSender, $e)
    Clear-Search
})

function Select-TreeItemByKey {
    # Expands the ancestor chain then selects the node matching $Key.
    # Returns $true if found and selected.
    param([string]$Key, [hashtable]$ItemsByKey, [hashtable]$AncestorsByKey)

    if (-not $ItemsByKey.ContainsKey($Key)) { return $false }

    foreach ($ancestor in $AncestorsByKey[$Key]) { $ancestor.IsExpanded = $true }
    $item = $ItemsByKey[$Key]
    $item.IsExpanded = $true
    $item.IsSelected = $true
    $item.BringIntoView()
    return $true
}

function Get-TreeSelectionRestoreInfo {
    # Captures a stable node reference for Restore-TreeSelection after a
    # Rebuild-Tree (old TreeViewItems are destroyed, but the category/group
    # keys stay the same). $Node defaults to the current selection.
    param($Node = $categoryTree.SelectedItem)
    $selected = $Node
    if ($null -eq $selected) { return $null }
    $tag = $selected.Tag
    switch ($tag.Kind) {
        'AdmxCategory' { return [pscustomobject]@{ Kind = 'AdmxCategory'; Key = "$($tag.CategoryId)|$($tag.Scope)" } }
        'SecurityCategory' { return [pscustomobject]@{ Kind = 'SecurityCategory'; Key = $tag.SecurityCategory } }
        'AdvancedAuditCategory' { return [pscustomobject]@{ Kind = 'AdvancedAuditCategory'; Key = $tag.AdvAuditCategory } }
        'Group' { return [pscustomobject]@{ Kind = 'Group'; Key = $tag.GroupId } }
        default { return $null }
    }
}

function Restore-TreeSelection {
    param($Info)
    if ($null -eq $Info -or -not $Info.Key) { return }
    switch ($Info.Kind) {
        'AdmxCategory' { [void](Select-TreeItemByKey -Key $Info.Key -ItemsByKey $script:TreeItemsByAdmxCategoryScope -AncestorsByKey $script:TreeAncestorsByKey) }
        'SecurityCategory' { [void](Select-TreeItemByKey -Key $Info.Key -ItemsByKey $script:TreeItemsBySecurityCategory -AncestorsByKey $script:TreeAncestorsBySecurityCategory) }
        'AdvancedAuditCategory' { [void](Select-TreeItemByKey -Key $Info.Key -ItemsByKey $script:TreeItemsByAdvAuditCategory -AncestorsByKey $script:TreeAncestorsByAdvAuditCategory) }
        'Group' { [void](Select-TreeItemByKey -Key $Info.Key -ItemsByKey $script:TreeItemsByGroupId -AncestorsByKey $script:TreeAncestorsByGroupId) }
    }
}

function Open-SearchResult {
    # Opens the edit dialog directly without navigating the tree first:
    # Open-SelectedPolicyEditor only needs Kind/PolicyId/Scope, already on
    # policyList.SelectedItem. Not touching the tree avoids briefly showing
    # the setting's "real" folder while the modal is open.
    $selectedItem = $policyList.SelectedItem
    if ($null -eq $selectedItem) { return }

    $ui = Get-CurrentUi
    $savedQuery = $searchBox.Text
    $hadActiveSearch = ($savedQuery -ne $ui.SearchPlaceholder) -and (-not [string]::IsNullOrWhiteSpace($savedQuery))

    Open-SelectedPolicyEditor

    # Modal already closed by this point. Refresh the search to reflect
    # any state change, keeping the scoped folder if any.
    if ($hadActiveSearch) {
        Invoke-Search -Query $savedQuery -PreserveScope
        if ($script:SearchScopedNode) {
            # Selection value is unchanged, so WPF won't re-fire
            # SelectedItemChanged - call explicitly instead.
            $script:SearchScopedNode.IsSelected = $true
            $script:SearchScopedNode.BringIntoView()
            Update-SearchResultsForSelectedCategory
        }
    }
}

function Show-AdminRequiredMessage {
    param([hashtable]$Ui)
    [System.Windows.MessageBox]::Show($Ui.AdminRequiredMessage, $Ui.AdminRequiredTitle, 'OK', 'Warning') | Out-Null
}

function Show-WriteErrorMessage {
    param([hashtable]$Ui, [string]$ErrorText)
    [System.Windows.MessageBox]::Show(($Ui.WriteErrorMessage -f $ErrorText), $Ui.WriteErrorTitle, 'OK', 'Error') | Out-Null
}

# --- Opening the edit dialog (double-click or Enter, as in gpedit.msc). --
# --- Writes immediately on OK, as in real gpedit.msc: no separate "Save"
# --- step. -----------------------------------------------------------
function Open-SelectedPolicyEditor {
    $selectedItem = $policyList.SelectedItem
    if ($null -eq $selectedItem) { return }
    $ui = Get-CurrentUi

    if ($selectedItem.Kind -eq 'Admx') {
        $pol = $script:admxIndex.policies | Where-Object { $_.id -eq $selectedItem.PolicyId } | Select-Object -First 1
        if (-not $pol) { return }
        $lookup = if ($selectedItem.Scope -eq 'Machine') { $machineLookup } else { $userLookup }
        $currentState = Get-AdmxPolicyState -Policy $pol -PolLookup $lookup
        $elementValues = Get-PolicyElementValues -Policy $pol -PolLookup $lookup

        $cisRec = Get-CisRecommendationForRegistry -CisIndex $script:CisIndex -RegistryKey $pol.registryKey -ValueName $pol.valueName
        $result = Show-AdmxEditDialog -Policy $pol -CurrentState $currentState -CurrentElementValues $elementValues -CisRecommendation $cisRec -Owner $window -ScriptRoot $PSScriptRoot -Ui $ui
        if (-not $result) { return }

        # Checked before admin check: in project mode, writes go into an
        # ordinary user folder, never under System32.
        if (-not $script:ActiveProject -and -not (Test-IsRunningAsAdministrator)) { Show-AdminRequiredMessage -Ui $ui; return }

        # In project mode, edits materialize the scope's temp file on
        # first change (seeded from the current working path), reused for
        # further changes this session. Real project files are only
        # touched by "Save now" or the initial File > Save.
        if ($script:ActiveProject) {
            if ($selectedItem.Scope -eq 'Machine') {
                $script:MachinePolPath = Get-OrCreateGpoTempFile -Key 'MachinePol' -SeedSource $script:MachinePolPath
            } else {
                $script:UserPolPath = Get-OrCreateGpoTempFile -Key 'UserPol' -SeedSource $script:UserPolPath
            }
        }

        try {
            $polPath = if ($selectedItem.Scope -eq 'Machine') { $MachinePolPath } else { $UserPolPath }
            # Never bump GPT.ini in project mode - Save-GpoProjectAs
            # doesn't persist it and nothing reads its version.
            $gptIniPathForSave = if ($script:ActiveProject) { $null } else { $GptIniPath }
            $newEntries = Save-AdmxChangeToFile -Policy $pol -Scope $selectedItem.Scope -NewState $result.State -ElementValues $result.ElementValues -PolPath $polPath -GptIniPath $gptIniPathForSave
            Write-GpEditSettingChangeLog -ParameterName $pol.displayName -Key "$($pol.registryKey)\$($pol.valueName)" -OldValue $currentState -NewValue $result.State

            if ($selectedItem.Scope -eq 'Machine') {
                $script:machineLookup = New-PolLookup -Entries $newEntries
            } else {
                $script:userLookup = New-PolLookup -Entries $newEntries
            }
            if ($script:ActiveProject) {
                $script:ProjectDirty = $true
                Update-SaveNowButtonVisibility
            }
            Update-PolicyList
        }
        catch {
            Show-WriteErrorMessage -Ui $ui -ErrorText $_.Exception.Message
        }
    }
    elseif ($selectedItem.Kind -eq 'Security') {
        $setting = $script:securityIndex.settings | Where-Object { $_.id -eq $selectedItem.PolicyId } | Select-Object -First 1
        if (-not $setting) { return }

        $cisRec = Get-CisRecommendationForSecuritySetting -CisIndex $script:CisIndex -Section $setting.section -Name $setting.name
        $result = Show-SecurityEditDialog -Setting $setting -CisRecommendation $cisRec -Owner $window -ScriptRoot $PSScriptRoot -Ui $ui -DataPath $script:AppSettings.paths.indexDir

        if ($script:__secDialogCatalogEdited) {
            # A catalog field was already written to disk by the dialog
            # itself - refresh even if the user then Cancels.
            $secPath = Join-Path $script:AppSettings.paths.indexDir 'security-index.json'
            & (Join-Path $PSScriptRoot 'Indexers\Build-SecurityIndex.ps1') -SecEditInfPath $SecEditInfPath -OutputPath $secPath
            $script:securityIndex = Get-Content -Raw -Encoding UTF8 $secPath | ConvertFrom-Json
            Update-PolicyList
        }

        if (-not $result) { return }

        if (-not $script:ActiveProject -and -not (Test-IsRunningAsAdministrator)) { Show-AdminRequiredMessage -Ui $ui; return }

        # In project mode, materializes temp_<suffix>.inf on the first
        # change (same pattern as the Admx branch above).
        if ($script:ActiveProject) {
            $script:SecEditInfPath = Get-OrCreateGpoTempFile -Key 'SecEditInf' -SeedSource $script:SecEditInfPath
        }

        try {
            Save-SecurityChangeToFile -SettingSection $setting.section -SettingName $setting.name -IsConfigured $result.IsConfigured -Value $result.Value -SecEditInfPath $SecEditInfPath
            Write-GpEditSettingChangeLog -ParameterName $setting.displayName -Key "$($setting.section)::$($setting.name)" -OldValue $setting.rawValue -NewValue $result.Value

            # secedit.inf modified; real application (secedit /import +
            # /configure) only happens when the window closes.
            $script:SecEditInfDirty = $true
            if ($script:ActiveProject) {
                $script:ProjectDirty = $true
                Update-SaveNowButtonVisibility
            }
            elseif ($setting.category -eq 'Security Options') {
                $script:SecurityOptionsDirty = $true
            }

            # Reloads the security index from the file just written, to
            # stay consistent with the source of truth on disk.
            $secPath = Join-Path $script:AppSettings.paths.indexDir 'security-index.json'
            & (Join-Path $PSScriptRoot 'Indexers\Build-SecurityIndex.ps1') -SecEditInfPath $SecEditInfPath -OutputPath $secPath
            $script:securityIndex = Get-Content -Raw -Encoding UTF8 $secPath | ConvertFrom-Json

            Update-PolicyList
        }
        catch {
            Show-WriteErrorMessage -Ui $ui -ErrorText $_.Exception.Message
        }
    }
    elseif ($selectedItem.Kind -eq 'AdvancedAudit') {
        $setting = $script:advancedAuditIndex.settings | Where-Object { $_.id -eq $selectedItem.PolicyId } | Select-Object -First 1
        if (-not $setting) { return }

        $cisRec = Get-CisRecommendationForAuditSubcategory -CisIndex $script:CisIndex -SubcategoryNameEn $setting.name
        $result = Show-SecurityEditDialog -Setting $setting -CisRecommendation $cisRec -Owner $window -ScriptRoot $PSScriptRoot -Ui $ui -DataPath $script:AppSettings.paths.indexDir
        if (-not $result) { return }

        if (-not $script:ActiveProject -and -not (Test-IsRunningAsAdministrator)) { Show-AdminRequiredMessage -Ui $ui; return }

        # In project mode, materializes temp_<suffix>.csv on the first
        # change (same pattern as the Admx branch above).
        if ($script:ActiveProject) {
            $script:AuditCsvPath = Get-OrCreateGpoTempFile -Key 'AuditCsv' -SeedSource $script:AuditCsvPath
        }

        try {
            # Never bump GPT.ini in project mode.
            $gptIniPathForSave = if ($script:ActiveProject) { $null } else { $GptIniPath }
            Save-AdvancedAuditChangeToFile -Guid $setting.guid -Name $setting.name -IsConfigured $result.IsConfigured -Value $result.Value -AuditCsvPath $AuditCsvPath -GptIniPath $gptIniPathForSave
            Write-GpEditSettingChangeLog -ParameterName $setting.displayName -Key $setting.guid -OldValue $setting.rawValue -NewValue $result.Value

            if ($script:ActiveProject) {
                $script:ProjectDirty = $true
                Update-SaveNowButtonVisibility
            }

            # Reloads the advanced audit index from the file just written.
            $auditIndexPath = Join-Path $script:AppSettings.paths.indexDir 'advanced-audit-index.json'
            & (Join-Path $PSScriptRoot 'Indexers\Build-AdvancedAuditIndex.ps1') -AuditCsvPath $AuditCsvPath -OutputPath $auditIndexPath
            $script:advancedAuditIndex = Get-Content -Raw -Encoding UTF8 $auditIndexPath | ConvertFrom-Json

            Update-PolicyList
        }
        catch {
            Show-WriteErrorMessage -Ui $ui -ErrorText $_.Exception.Message
        }
    }
}

$policyList.Add_MouseDoubleClick({
    param($EventSender, $e)
    if ($script:IsSearchActive) { Open-SearchResult } else { Open-SelectedPolicyEditor }
})

$policyList.Add_KeyDown({
    param($EventSender, $e)
    if ($e.Key -eq [System.Windows.Input.Key]::Enter) {
        if ($script:IsSearchActive) { Open-SearchResult } else { Open-SelectedPolicyEditor }
        $e.Handled = $true
    }
})

# --- Save now (project mode only: pushes working/temp files to the saved
# project folder - see Save-GpoProjectChanges) ------------------------------
$saveNowButton.Add_Click({
    param($EventSender, $e)
    if ($script:ActiveProject -and $script:ActiveProject.Saved) {
        Invoke-SaveGpoProjectNow
    } else {
        # Same Save As fallback as fileSaveMenuItem.Add_Click.
        Save-GpoProjectAs
    }
})

# --- Closing the main window (X button/Alt+F4) -----------------------------
# Two independent steps:
# 1) If a GPO session has anything unsaved, ask what to do
#    (Show-UnsavedProjectCloseDialog) - Cancel abandons the close entirely.
# 2) Real application of Account Policies/Local Policies (secedit
#    /import + /configure): only runs if secedit.inf changed this session
#    AND outside project mode (in project mode secedit.inf lives in the
#    project folder; system application must never trigger there).
# Temp files are always purged afterward if the close proceeds. A
# Ctrl+C/crash does not trigger this handler - changes then stay only in
# secedit.inf/temp files and are lost.
$window.Add_Closing({
    param($closingSender, $e)
    $ui = Get-CurrentUi

    if ($script:ActiveProject -and (-not $script:ActiveProject.Saved -or $script:ProjectDirty)) {
        $alreadySaved = $script:ActiveProject.Saved
        $choice = Show-UnsavedProjectCloseDialog -Owner $window -ScriptRoot $PSScriptRoot -Ui $ui -AlreadySaved:$alreadySaved
        if ($choice -eq 'Cancel') {
            $e.Cancel = $true
            return
        }
        if ($choice -eq 'Save') {
            if ($alreadySaved) {
                # Push pending changes like "Save now". On failure, cancel
                # the close so nothing is silently lost.
                try {
                    Save-GpoProjectChanges
                }
                catch {
                    Show-WriteErrorMessage -Ui $ui -ErrorText $_.Exception.Message
                    $e.Cancel = $true
                    return
                }
            }
            else {
                Save-GpoProjectAs
                if (-not $script:ActiveProject.Saved) {
                    # Save As was cancelled - don't close, changes would be
                    # stuck in temp files about to be purged.
                    $e.Cancel = $true
                    return
                }
            }
        }
        # $choice -eq 'Continue': close without saving, carry on.
    }

    if ($script:SecEditInfDirty -and -not $script:ActiveProject) {
        if (-not (Test-IsRunningAsAdministrator)) {
            Show-AdminRequiredMessage -Ui $ui
        }
        else {
            try {
                $applyResult = Invoke-SecEditInfApply -SecEditInfPath $SecEditInfPath -RegistryValuesBaselineKeys $script:RegistryValuesBaselineKeys
                if ($applyResult.ExitCode -ne 0) {
                    Show-WriteErrorMessage -Ui $ui -ErrorText $applyResult.Output
                }
            }
            catch {
                Show-WriteErrorMessage -Ui $ui -ErrorText $_.Exception.Message
            }
        }
    }

    Remove-GpoTempFiles
})

[void]$window.ShowDialog()
