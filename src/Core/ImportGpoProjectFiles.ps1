<#
    "File > Import" - reads an exported Group Policy project folder (same
    layout Export-GpoProjectFiles writes, see GpEdit.ps1) and applies it FOR
    REAL, IMMEDIATELY, to the live machine (secedit.sdb, real registry.pol
    paths + gpupdate /force, real audit.csv + auditpol /restore) -
    independent of $script:ActiveProject, unlike every other File-menu
    action. See plan-gpedit-import.md (decision log) for the design
    rationale confirmed with the user.

    Always targets the real system via $script:Real*Path (GpEdit.ps1,
    captured once at launch, never reassigned) - never the mutable
    $script:MachinePolPath/etc., which Set-ActiveGpoProject/
    Start-UnsavedGpoSession redirect to a project's own files while one is
    active.
#>

Set-StrictMode -Version Latest

# --- Folder pick + manifest resolution ------------------------------------

function Select-GpoImportManifestPath {
    # Same Explorer-style dialog Open-GpoProject already uses (GpEdit.ps1):
    # OpenFileDialog filtered to *_Info.xml, not the tree-view
    # FolderBrowserDialog used previously - the user asked to reuse the
    # already-established browse dialog instead. Returns the chosen
    # <name>_Info.xml path, or $null on Cancel.
    param([Parameter(Mandatory)][hashtable]$Ui)
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title = $Ui.ImportGpoDialogTitle
    $dialog.Filter = 'GPedit Project Manifest (*_Info.xml)|*_Info.xml'
    $dialog.InitialDirectory = $script:AppSettings.paths.importExportDir
    if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
    return $dialog.FileName
}

function Resolve-GpoImportFiles {
    # Combines the EXISTING Get-GpoProjectManifest (GpEdit.ps1) with the
    # chosen manifest's parent folder to resolve the 4 real file paths.
    # $null on anything malformed/incomplete/missing.
    param([Parameter(Mandatory)][string]$ManifestPath)
    $manifest = Get-GpoProjectManifest -Path $ManifestPath
    if (-not $manifest) { return $null }
    $folderPath = Split-Path -Parent $ManifestPath

    $f = $manifest.Files
    $paths = [pscustomobject]@{
        Name           = $manifest.Name
        MachinePolPath = Join-Path $folderPath $f.machinePol
        UserPolPath    = Join-Path $folderPath $f.userPol
        SecEditInfPath = Join-Path $folderPath $f.secEditInf
        AuditCsvPath   = Join-Path $folderPath $f.auditCsv
    }
    foreach ($p in @($paths.MachinePolPath, $paths.UserPolPath, $paths.SecEditInfPath, $paths.AuditCsvPath)) {
        if (-not (Test-Path -LiteralPath $p)) { return $null }
    }
    return $paths
}

# --- Live snapshot readers (always the real machine) -----------------------

function Get-LiveSecEditInf {
    # Fresh `secedit /export` to a throwaway $env:TEMP path (never the app's
    # own cached data\secedit.inf, never a project's file) so the diff never
    # depends on a stale snapshot. Reuses the existing Invoke-SecEditInfExport
    # (ChangeApplier.ps1) as-is. Returns the temp path; caller is responsible
    # for deleting it when done.
    $tempPath = Join-Path $env:TEMP "gpedit-import-live-$([guid]::NewGuid().ToString('N')).inf"
    $exportResult = Invoke-SecEditInfExport -SecEditInfPath $tempPath
    if ($exportResult.ExitCode -ne 0) { throw $exportResult.Output }
    return $tempPath
}

function Get-LiveMachinePolEntries { return , (Get-PolFileEntriesSafe -Path $script:RealMachinePolPath) }
function Get-LiveUserPolEntries { return , (Get-PolFileEntriesSafe -Path $script:RealUserPolPath) }
function Get-LiveAuditCsvRows { return Read-AuditCsv -Path $script:RealAuditCsvPath }

# --- Diff engine -------------------------------------------------------------

function Get-DiffIndexPair {
    # Runs Build-SecurityIndex.ps1/Build-AdvancedAuditIndex.ps1 TWICE each
    # (once against the live snapshot, once against the imported files) to
    # throwaway JSON - reuses the app's own index builders rather than
    # writing bespoke catalog-walking code. Returns the 4 flat settings
    # arrays plus an id-keyed hashtable for each, for O(1) live-vs-import
    # lookup (id = "$section::$name" for security, "AdvAudit::{guid}" for
    # audit - see Build-SecurityIndex.ps1/Build-AdvancedAuditIndex.ps1).
    param(
        [Parameter(Mandatory)][string]$ScriptRoot,
        [Parameter(Mandatory)][string]$LiveSecEditInfPath,
        [Parameter(Mandatory)][string]$ImportSecEditInfPath,
        [Parameter(Mandatory)][string]$LiveAuditCsvPath,
        [Parameter(Mandatory)][string]$ImportAuditCsvPath
    )

    $tmp = Join-Path $env:TEMP "gpedit-import-diff-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    try {
        $secLivePath = Join-Path $tmp 'sec-live.json'
        $secImportPath = Join-Path $tmp 'sec-import.json'
        $audLivePath = Join-Path $tmp 'aud-live.json'
        $audImportPath = Join-Path $tmp 'aud-import.json'

        & (Join-Path $ScriptRoot 'Indexers\Build-SecurityIndex.ps1') -SecEditInfPath $LiveSecEditInfPath -OutputPath $secLivePath | Out-Null
        & (Join-Path $ScriptRoot 'Indexers\Build-SecurityIndex.ps1') -SecEditInfPath $ImportSecEditInfPath -OutputPath $secImportPath | Out-Null
        & (Join-Path $ScriptRoot 'Indexers\Build-AdvancedAuditIndex.ps1') -AuditCsvPath $LiveAuditCsvPath -OutputPath $audLivePath | Out-Null
        & (Join-Path $ScriptRoot 'Indexers\Build-AdvancedAuditIndex.ps1') -AuditCsvPath $ImportAuditCsvPath -OutputPath $audImportPath | Out-Null

        $secLive = @((Get-Content -Raw -Encoding UTF8 $secLivePath | ConvertFrom-Json).settings)
        $secImport = @((Get-Content -Raw -Encoding UTF8 $secImportPath | ConvertFrom-Json).settings)
        $audLive = @((Get-Content -Raw -Encoding UTF8 $audLivePath | ConvertFrom-Json).settings)
        $audImport = @((Get-Content -Raw -Encoding UTF8 $audImportPath | ConvertFrom-Json).settings)

        $secImportById = @{}
        foreach ($s in $secImport) { $secImportById[$s.id] = $s }
        $audImportById = @{}
        foreach ($s in $audImport) { $audImportById[$s.id] = $s }

        return [pscustomobject]@{
            SecurityLive       = $secLive
            SecurityImportById = $secImportById
            AuditLive          = $audLive
            AuditImportById    = $audImportById
        }
    }
    finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-SecurityOptionsRemovalCandidates {
    # STANDARD mode's check, scoped to categories == 'Security Options' and
    # 'User Rights Assignment' (the same pairing already treated alike
    # elsewhere - see $script:StateWideSecurityCategories in GpEdit.ps1; not
    # widened further to Account Policies): settings currently defined live
    # that are NOT defined in the import.
    # Empty result => caller skips the confirmation dialog entirely.
    param([Parameter(Mandatory)]$DiffIndexPair, [Parameter(Mandatory)][hashtable]$Ui)

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($live in $DiffIndexPair.SecurityLive) {
        if ($live.category -ne 'Security Options' -and $live.category -ne 'User Rights Assignment') { continue }
        if (-not $live.isConfigured) { continue }
        $import = $DiffIndexPair.SecurityImportById[$live.id]
        if ($import -and $import.isConfigured) { continue }

        $rows.Add([pscustomobject]@{
            Kind             = 'Security'
            Id               = $live.id
            CatalogName      = $live.name
            Name             = "$($live.category) - $($live.displayName)"
            Section          = $live.section
            Scope            = $null
            Guid             = $null
            PolicyId         = $null
            CurrentState     = (Format-SecuritySettingValue -Setting $live -Ui $Ui)
            ImportState      = $Ui.StateNotDefined
            Location         = $null
            LiveIsConfigured = $true
            LiveRawValue     = $live.rawValue
            IsSelected       = $true
        })
    }
    return , $rows
}

function Get-GranularSecurityDiffRows {
    # GRANULAR mode: every secedit.inf-backed category in one pass (Account
    # Policies, User Rights Assignment, Security Options, Audit Policy - the
    # catalog already flattens all of them, see Get-SecurityCatalogEntries).
    # Change = currently defined AND (removed or value differs). Add =
    # currently undefined, defined by the import.
    param([Parameter(Mandatory)]$DiffIndexPair, [Parameter(Mandatory)][hashtable]$Ui)

    $changeRows = New-Object System.Collections.Generic.List[object]
    $addRows = New-Object System.Collections.Generic.List[object]

    foreach ($live in $DiffIndexPair.SecurityLive) {
        $import = $DiffIndexPair.SecurityImportById[$live.id]
        $importConfigured = ($import -and $import.isConfigured)
        if (-not $live.isConfigured -and -not $importConfigured) { continue }

        $displayName = "$($live.category) - $($live.displayName)"

        if (-not $live.isConfigured -and $importConfigured) {
            $addRows.Add([pscustomobject]@{
                Kind             = 'Security'
                Id               = $live.id
                CatalogName      = $live.name
                Name             = $displayName
                Section          = $live.section
                Scope            = $null
                Guid             = $null
                PolicyId         = $null
                CurrentState     = $null
                ImportState      = (Format-SecuritySettingValue -Setting $import -Ui $Ui)
                Location         = (Get-SecurityTechnicalDetailText -Setting $live -Ui $Ui)
                LiveIsConfigured = $false
                LiveRawValue     = $null
                IsSelected       = $true
            })
            continue
        }

        # $live.isConfigured is $true from here on.
        if ($importConfigured -and $import.rawValue -eq $live.rawValue) { continue }

        $changeRows.Add([pscustomobject]@{
            Kind             = 'Security'
            Id               = $live.id
            CatalogName      = $live.name
            Name             = $displayName
            Section          = $live.section
            Scope            = $null
            Guid             = $null
            PolicyId         = $null
            CurrentState     = (Format-SecuritySettingValue -Setting $live -Ui $Ui)
            ImportState      = $(if ($importConfigured) { Format-SecuritySettingValue -Setting $import -Ui $Ui } else { $Ui.StateNotDefined })
            Location         = $null
            LiveIsConfigured = $true
            LiveRawValue     = $live.rawValue
            IsSelected       = $true
        })
    }
    return [pscustomobject]@{ Change = $changeRows; Add = $addRows }
}

function Get-GranularAuditDiffRows {
    # Same Change/Add split as Get-GranularSecurityDiffRows, over the
    # Advanced Audit settings array. Build-AdvancedAuditIndex.ps1's item
    # shape (isConfigured/rawValue/valueType='audit') matches what
    # Format-SecuritySettingValue already expects, so it is reused as-is -
    # no separate audit-only formatter needed.
    param([Parameter(Mandatory)]$DiffIndexPair, [Parameter(Mandatory)][hashtable]$Ui)

    $changeRows = New-Object System.Collections.Generic.List[object]
    $addRows = New-Object System.Collections.Generic.List[object]

    foreach ($live in $DiffIndexPair.AuditLive) {
        $import = $DiffIndexPair.AuditImportById[$live.id]
        $importConfigured = ($import -and $import.isConfigured)
        if (-not $live.isConfigured -and -not $importConfigured) { continue }

        $categoryLabel = $Ui["AdvAudit$($live.category)"]
        if (-not $categoryLabel) { $categoryLabel = $live.category }
        $displayName = "$categoryLabel - $($live.displayName)"

        if (-not $live.isConfigured -and $importConfigured) {
            $addRows.Add([pscustomobject]@{
                Kind             = 'AdvancedAudit'
                Id               = $live.id
                CatalogName      = $null
                Name             = $displayName
                Section          = $null
                Scope            = $null
                Guid             = $live.guid
                PolicyId         = $null
                CurrentState     = $null
                ImportState      = (Format-SecuritySettingValue -Setting $import -Ui $Ui)
                Location         = (Get-AdvancedAuditTechnicalDetailText -Setting $live -Ui $Ui)
                LiveIsConfigured = $false
                LiveRawValue     = $null
                IsSelected       = $true
            })
            continue
        }

        if ($importConfigured -and $import.rawValue -eq $live.rawValue) { continue }

        $changeRows.Add([pscustomobject]@{
            Kind             = 'AdvancedAudit'
            Id               = $live.id
            CatalogName      = $null
            Name             = $displayName
            Section          = $null
            Scope            = $null
            Guid             = $live.guid
            PolicyId         = $null
            CurrentState     = (Format-SecuritySettingValue -Setting $live -Ui $Ui)
            ImportState      = $(if ($importConfigured) { Format-SecuritySettingValue -Setting $import -Ui $Ui } else { $Ui.StateNotDefined })
            Location         = $null
            LiveIsConfigured = $true
            LiveRawValue     = $live.rawValue
            IsSelected       = $true
        })
    }
    return [pscustomobject]@{ Change = $changeRows; Add = $addRows }
}

function Get-AdmxPolicyStateSummaryText {
    # Base Enabled/Disabled/Not Configured label (Get-AdmxPolicyStateLabel,
    # PolicyState.ps1) plus configured element values, resolving enum choices
    # to their .adml display labels (Build-AdmxIndex.ps1's element shape:
    # .id/.type/.label/.items[].value/.items[].displayName) where available.
    # Nothing at this fidelity exists elsewhere in the app today - flagged in
    # the plan as the highest-risk net-new piece.
    param($Policy, [Parameter(Mandatory)][string]$State, [Parameter(Mandatory)][hashtable]$PolLookup, [Parameter(Mandatory)][hashtable]$Ui)

    $label = Get-AdmxPolicyStateLabel -State $State -Ui $Ui
    if ($State -ne 'Enabled') { return $label }

    $values = Get-PolicyElementValues -Policy $Policy -PolLookup $PolLookup
    if ($values.Count -eq 0) { return $label }

    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($el in @($Policy.elements)) {
        if (-not $values.ContainsKey($el.id)) { continue }
        $raw = $values[$el.id]
        $display = $null
        if ($el.type -eq 'enum') {
            $item = @($el.items) | Where-Object { "$($_.value)" -eq "$raw" } | Select-Object -First 1
            $display = $(if ($item) { $item.displayName } else { "$raw" })
        }
        elseif ($raw -is [array]) {
            $display = ($raw -join '; ')
        }
        else {
            $display = "$raw"
        }
        $elLabel = $(if ($el.label) { $el.label } else { $el.id })
        $parts.Add("$elLabel = $display")
    }
    if ($parts.Count -eq 0) { return $label }
    return "$label ($($parts -join ', '))"
}

function Get-GranularAdmxDiffRows {
    # Administrative Templates have no prebuilt index-from-arbitrary-.pol
    # builder (unlike Security/Advanced Audit) - walks the in-memory ADMX
    # policy list ($script:admxIndex.policies, already loaded at startup)
    # against 4 PolLookups per scope (Machine/User independently, since a
    # 'Both'-class policy can be configured differently - or not at all - in
    # each). Id is scope-qualified ("<policyId>|<scope>"), same convention
    # already used for pending-change keys elsewhere (Apply-AdmxChangesToEntries).
    param(
        [Parameter(Mandatory)][hashtable]$LiveMachineLookup,
        [Parameter(Mandatory)][hashtable]$LiveUserLookup,
        [Parameter(Mandatory)][hashtable]$ImportMachineLookup,
        [Parameter(Mandatory)][hashtable]$ImportUserLookup,
        [Parameter(Mandatory)][hashtable]$Ui
    )

    $changeRows = New-Object System.Collections.Generic.List[object]
    $addRows = New-Object System.Collections.Generic.List[object]
    $categoryPrefix = $Ui.ImportCategoryAdministrativeTemplates

    foreach ($pol in $script:admxIndex.policies) {
        foreach ($scope in @('Machine', 'User')) {
            if (-not (Test-PolicyMatchesScope -PolicyClass $pol.class -Scope $scope)) { continue }

            $liveLookup = $(if ($scope -eq 'Machine') { $LiveMachineLookup } else { $LiveUserLookup })
            $importLookup = $(if ($scope -eq 'Machine') { $ImportMachineLookup } else { $ImportUserLookup })

            $liveState = Get-AdmxPolicyState -Policy $pol -PolLookup $liveLookup
            $importState = Get-AdmxPolicyState -Policy $pol -PolLookup $importLookup
            if ($liveState -eq 'NotConfigured' -and $importState -eq 'NotConfigured') { continue }

            $liveText = Get-AdmxPolicyStateSummaryText -Policy $pol -State $liveState -PolLookup $liveLookup -Ui $Ui
            $importText = Get-AdmxPolicyStateSummaryText -Policy $pol -State $importState -PolLookup $importLookup -Ui $Ui

            $id = "$($pol.id)|$scope"
            $displayName = "$categoryPrefix - $($pol.displayName) [$scope]"

            if ($liveState -eq 'NotConfigured') {
                $addRows.Add([pscustomobject]@{
                    Kind             = 'Admx'
                    Id               = $id
                    CatalogName      = $null
                    Name             = $displayName
                    Section          = $null
                    Scope            = $scope
                    Guid             = $null
                    PolicyId         = $pol.id
                    CurrentState     = $null
                    ImportState      = $importText
                    Location         = (Get-AdmxTechnicalDetailText -Policy $pol -Scope $scope -Ui $Ui)
                    LiveIsConfigured = $false
                    LiveRawValue     = $null
                    IsSelected       = $true
                })
                continue
            }

            if ($importState -eq $liveState -and $importText -eq $liveText) { continue }

            $changeRows.Add([pscustomobject]@{
                Kind             = 'Admx'
                Id               = $id
                CatalogName      = $null
                Name             = $displayName
                Section          = $null
                Scope            = $scope
                Guid             = $null
                PolicyId         = $pol.id
                CurrentState     = $liveText
                ImportState      = $importText
                Location         = $null
                LiveIsConfigured = $true
                LiveRawValue     = $null
                IsSelected       = $true
            })
        }
    }
    return [pscustomobject]@{ Change = $changeRows; Add = $addRows }
}

# --- "Restore unchecked rows to their current live value" merges -----------

function Restore-UncheckedSecurityRowsToImportGpt {
    # Re-injects each unchecked row's CURRENT LIVE value into the parsed
    # import GptTmpl, so a row the user leaves unchecked is not touched by
    # the import. Reuses the existing Apply-SecurityChangesToGpt (PolicyWriter.ps1)
    # as-is.
    param([Parameter(Mandatory)]$ImportGpt, [object[]]$UncheckedRows, [Parameter(Mandatory)][hashtable]$SettingsById)

    $pending = @{}
    foreach ($row in @($UncheckedRows | Where-Object { $_ })) {
        $pending[$row.Id] = @{ IsConfigured = $row.LiveIsConfigured; Value = $row.LiveRawValue }
    }
    if ($pending.Count -gt 0) {
        Apply-SecurityChangesToGpt -GptTmpl $ImportGpt -PendingChanges $pending -SettingsById $SettingsById | Out-Null
    }
    return $ImportGpt
}

function Restore-UncheckedAdmxRowsToImportEntries {
    # Same idea for registry.pol: reuses the existing Merge-PolEntriesForPolicy
    # (PolicyWriter.ps1) per unchecked row, applied on top of the imported
    # .pol entries for the given scope.
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$ImportEntries,
        [object[]]$UncheckedRows,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][hashtable]$PoliciesById,
        [Parameter(Mandatory)][hashtable]$LiveLookup
    )

    $entries = $ImportEntries
    foreach ($row in ($UncheckedRows | Where-Object { $_ -and $_.Scope -eq $Scope })) {
        if (-not $PoliciesById.ContainsKey($row.PolicyId)) { continue }
        $pol = $PoliciesById[$row.PolicyId]
        $liveState = Get-AdmxPolicyState -Policy $pol -PolLookup $LiveLookup
        $liveValues = Get-PolicyElementValues -Policy $pol -PolLookup $LiveLookup
        $entries = Merge-PolEntriesForPolicy -Entries $entries -Policy $pol -NewState $liveState -ElementValues $liveValues
    }
    return , $entries
}

function Restore-UncheckedAuditRowsToImportRows {
    # Same idea for audit.csv: no merge primitive exists for this format
    # elsewhere in the app, small enough to write directly with the existing
    # Set-AuditCsvValue/Remove-AuditCsvValue (AuditCsvFile.ps1).
    param([Parameter(Mandatory)][hashtable]$ImportRows, [object[]]$UncheckedRows, [Parameter(Mandatory)][hashtable]$LiveRows)

    foreach ($row in ($UncheckedRows | Where-Object { $_ })) {
        $liveRow = Get-AuditCsvValue -Rows $LiveRows -Guid $row.Guid
        if ($liveRow) {
            Set-AuditCsvValue -Rows $ImportRows -Guid $row.Guid -SubcategoryName $liveRow['Subcategory'] -SettingValue ([int]$liveRow['Setting Value'])
        }
        else {
            Remove-AuditCsvValue -Rows $ImportRows -Guid $row.Guid
        }
    }
}

function Get-RegistryValuesBaselineKeysForImport {
    # Only CHECKED Security-Options removal rows backed by [Registry Values]
    # need this - [System Access]/[Privilege Rights] rows are already
    # naturally dropped by `secedit /import /overwrite` itself. Feeds the
    # existing Remove-TattooedRegistryValues via
    # Invoke-SecEditInfApply -RegistryValuesBaselineKeys (ChangeApplier.ps1) -
    # no changes needed there, it already does exactly "remove the real
    # registry value for a key that disappeared between baseline and now".
    param([object[]]$CheckedRemovalRows)

    $keys = @{}
    foreach ($row in ($CheckedRemovalRows | Where-Object { $_ -and $_.Kind -eq 'Security' -and $_.Section -eq 'Registry Values' })) {
        $keys[$row.CatalogName] = $true
    }
    return $keys
}

# --- Backup + rollback -------------------------------------------------------

function Backup-LiveGpoFilesForImport {
    # Timestamped backup of the 3 real target stores (the fresh live secedit
    # export, both real .pol files, the real audit.csv) before any real
    # write - reuses the existing New-TimestampedBackup (PolicyWriter.ps1),
    # same convention as Get-OrCreateSessionBackup. Returns the backup dir,
    # or $null if nothing existed to back up.
    param([Parameter(Mandatory)][string]$LiveSecEditInfPath)

    $filesToBackup = @{}
    if (Test-Path -LiteralPath $LiveSecEditInfPath) { $filesToBackup['secedit.inf'] = $LiveSecEditInfPath }
    if (Test-Path -LiteralPath $script:RealMachinePolPath) { $filesToBackup['Machine_registry.pol'] = $script:RealMachinePolPath }
    if (Test-Path -LiteralPath $script:RealUserPolPath) { $filesToBackup['User_registry.pol'] = $script:RealUserPolPath }
    if (Test-Path -LiteralPath $script:RealAuditCsvPath) { $filesToBackup['audit.csv'] = $script:RealAuditCsvPath }
    if ($filesToBackup.Count -eq 0) { return $null }

    $result = New-TimestampedBackup -FilesToBackup $filesToBackup -BackupRoot $script:BackupRoot
    return $result.BackupDir
}

function Restore-LiveGpoFilesFromImportBackup {
    # Replays the pre-import backup through the SAME apply primitives used
    # for a real import - since the backup captured the pre-import live
    # state, re-applying it undoes the failed import. Success deletes the
    # backup dir; failure keeps it (caller surfaces its path for manual
    # recovery), per the user's explicit choice.
    param([Parameter(Mandatory)][string]$BackupDir)

    try {
        $secBackupPath = Join-Path $BackupDir 'secedit.inf'
        if (Test-Path -LiteralPath $secBackupPath) {
            $secResult = Invoke-SecEditInfApply -SecEditInfPath $secBackupPath
            if ($secResult.ExitCode -ne 0) { throw $secResult.Output }
        }

        $machineBackupPath = Join-Path $BackupDir 'Machine_registry.pol'
        $userBackupPath = Join-Path $BackupDir 'User_registry.pol'
        if ((Test-Path -LiteralPath $machineBackupPath) -or (Test-Path -LiteralPath $userBackupPath)) {
            $machineEntries = $(if (Test-Path -LiteralPath $machineBackupPath) { Read-PolFile -Path $machineBackupPath } else { New-Object System.Collections.Generic.List[object] })
            $userEntries = $(if (Test-Path -LiteralPath $userBackupPath) { Read-PolFile -Path $userBackupPath } else { New-Object System.Collections.Generic.List[object] })
            $admxResult = Invoke-ImportAdmxApply -MachineEntries $machineEntries -UserEntries $userEntries
            if ($admxResult.ExitCode -ne 0) { throw $admxResult.Output }
        }

        $auditBackupPath = Join-Path $BackupDir 'audit.csv'
        if (Test-Path -LiteralPath $auditBackupPath) {
            $backedUpRows = Read-AuditCsv -Path $auditBackupPath
            $audResult = Invoke-ImportAuditCsvApply -MergedRows $backedUpRows
            if ($audResult.ExitCode -ne 0) { throw $audResult.Output }
        }

        Remove-Item -LiteralPath $BackupDir -Recurse -Force -ErrorAction Stop
        return [pscustomobject]@{ Success = $true; Error = $null }
    }
    catch {
        return [pscustomobject]@{ Success = $false; Error = $_.Exception.Message }
    }
}

# --- Live-apply functions (real writes) -------------------------------------

function Invoke-ImportSecEditApply {
    # secedit-backed categories: thin wrapper, all real work already exists
    # (Invoke-SecEditInfApply, ChangeApplier.ps1).
    param([Parameter(Mandatory)]$ImportGpt, [Parameter(Mandatory)][hashtable]$RegistryValuesBaselineKeys)

    $applyPath = Join-Path $env:TEMP "gpedit-import-apply-$([guid]::NewGuid().ToString('N')).inf"
    try {
        Write-GptTmplInf -Path $applyPath -GptTmpl $ImportGpt
        return Invoke-SecEditInfApply -SecEditInfPath $applyPath -RegistryValuesBaselineKeys $RegistryValuesBaselineKeys
    }
    finally {
        Remove-Item -LiteralPath $applyPath -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-ImportAdmxApply {
    # NEW - no live-apply path exists for .pol anywhere else in the app
    # (every other write just writes the file, real application is implicit
    # via Windows' own gpsvc polling, never forced). Writes to the REAL
    # $script:RealMachinePolPath/$script:RealUserPolPath, bumps the real
    # GPT.ini, then forces gpupdate so it takes effect immediately - per the
    # user's explicit choice (accepted side effect: reapplies ALL machine+
    # user policy, not just the imported subset).
    # AllowEmptyCollection: a Mandatory List[object] parameter otherwise
    # rejects a real, valid empty list (e.g. no User-scope policies exported)
    # with "Cannot bind argument ... because it is an empty collection" - a
    # PowerShell 5.1 binder quirk that only affects List/array parameters,
    # not hashtables.
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$MachineEntries,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$UserEntries
    )

    Write-PolFile -Path $script:RealMachinePolPath -Entries $MachineEntries
    Write-PolFile -Path $script:RealUserPolPath -Entries $UserEntries

    $gptIni = Read-GptIni -Path $script:RealGptIniPath
    Step-GptIniVersion -GptIni $gptIni -IncrementMachine -IncrementUser | Out-Null
    Write-GptIni -Path $script:RealGptIniPath -GptIni $gptIni

    $output = & gpupdate.exe /force 2>&1 | Out-String
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
}

function Invoke-ImportAuditCsvApply {
    # NEW - no auditpol wrapper exists anywhere else in the app. Writes the
    # real audit.csv then `auditpol /restore` - the canonical mechanism for
    # this exact file format (AuditCsvFile.ps1's own header comments already
    # note the format mirrors `auditpol /backup` output).
    param([Parameter(Mandatory)][hashtable]$MergedRows)

    Write-AuditCsv -Path $script:RealAuditCsvPath -Rows $MergedRows
    $output = & auditpol.exe /restore /file:"$script:RealAuditCsvPath" 2>&1 | Out-String
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
}

# --- Dialogs -----------------------------------------------------------------

function Show-ImportModeDialog {
    # Standard/Granular radio choice. Returns 'Standard'/'Granular', or
    # $null on Cancel.
    param($Owner, [string]$ScriptRoot, [Parameter(Mandatory)][hashtable]$Ui)

    $window = Import-XamlWindow -ScriptRoot $ScriptRoot -Name 'ImportModeWindow' -Owner $Owner
    $window.Title = $Ui.ImportModeWindowTitle
    $standardRadio = $window.FindName('ImportModeStandardRadioButton')
    $granularRadio = $window.FindName('ImportModeGranularRadioButton')
    $standardRadio.Content = $Ui.ImportModeStandard
    $granularRadio.Content = $Ui.ImportModeGranular

    $okButton = $window.FindName('OkButton')
    $cancelButton = $window.FindName('CancelButton')
    $okButton.Content = $Ui.ApplyButton
    $cancelButton.Content = $Ui.CancelButton

    $okButton.Add_Click({ param($EventSender, $e) $window.DialogResult = $true })
    $cancelButton.Add_Click({ param($EventSender, $e) $window.DialogResult = $false })

    if ($window.ShowDialog()) {
        if ($granularRadio.IsChecked) { return 'Granular' }
        return 'Standard'
    }
    return $null
}

function Show-ImportConfirmationDialog {
    # Shared review window for both Standard's single table and Granular's
    # Change/Add tabs. Returns [pscustomobject]@{ ChangeRows = ... } (each
    # row's final .IsSelected reflecting the user's checkbox choices), or
    # $null on Cancel - which the caller must treat as aborting the WHOLE
    # import, not just this review step.
    param($Owner, [string]$ScriptRoot, [Parameter(Mandatory)][hashtable]$Ui, [object[]]$ChangeRows, [object[]]$AddRows)

    $window = Import-XamlWindow -ScriptRoot $ScriptRoot -Name 'ImportConfirmationWindow' -Owner $Owner
    $window.Title = $Ui.ImportConfirmationWindowTitle
    $changeTab = $window.FindName('ImportChangeTabItem')
    $addTab = $window.FindName('ImportAddTabItem')
    $changeTab.Header = $Ui.ImportChangeTabHeader
    $addTab.Header = $Ui.ImportAddTabHeader

    $selectAllCheck = $window.FindName('ImportChangeSelectAllCheckBox')
    $selectAllCheck.Content = $Ui.SelectAllLabel
    $changeGrid = $window.FindName('ImportChangeGrid')
    $addGrid = $window.FindName('ImportAddGrid')

    $changeList = New-Object System.Collections.ObjectModel.ObservableCollection[object]
    foreach ($row in @($ChangeRows)) { $changeList.Add($row) }
    $changeGrid.ItemsSource = $changeList

    if (@($AddRows).Count -gt 0) {
        $addGrid.ItemsSource = @($AddRows)
    }
    else {
        $addTab.Visibility = 'Collapsed'
    }

    $selectAllCheck.Add_Click({
        param($EventSender, $e)
        foreach ($row in $changeList) { $row.IsSelected = $selectAllCheck.IsChecked }
        $changeGrid.Items.Refresh()
    })

    $okButton = $window.FindName('OkButton')
    $cancelButton = $window.FindName('CancelButton')
    $okButton.Content = $Ui.ApplyButton
    $cancelButton.Content = $Ui.CancelButton

    $script:__importConfirmResult = $null
    $okButton.Add_Click({
        param($EventSender, $e)
        # @($changeList | ForEach-Object { $_ }), not bare @($changeList) -
        # the pipeline form is the confirmed-safe way to snapshot an existing
        # collection variable into a plain array on this machine (see the
        # @()-around-a-List[object] footgun noted elsewhere in this file).
        $script:__importConfirmResult = [pscustomobject]@{ ChangeRows = @($changeList | ForEach-Object { $_ }) }
        $window.DialogResult = $true
    })
    $cancelButton.Add_Click({ param($EventSender, $e) $window.DialogResult = $false })

    if ($window.ShowDialog()) { return $script:__importConfirmResult }
    return $null
}

# --- Top-level orchestrator ---------------------------------------------------

function Import-GpoProjectFiles {
    # "File > Import" entry point. See the header comment of this file and
    # plan-gpedit-import.md for the full design.
    $ui = Get-CurrentUi

    $manifestPath = Select-GpoImportManifestPath -Ui $ui
    if (-not $manifestPath) { return }

    $importFiles = Resolve-GpoImportFiles -ManifestPath $manifestPath
    if (-not $importFiles) {
        [System.Windows.MessageBox]::Show($ui.OpenGpoInvalidProjectMessage, $ui.ErrorTitle, 'OK', 'Warning') | Out-Null
        return
    }

    $mode = Show-ImportModeDialog -Owner $window -ScriptRoot $PSScriptRoot -Ui $ui
    if (-not $mode) { return }

    $liveSecEditInfPath = $null
    try {
        try {
            $liveSecEditInfPath = Get-LiveSecEditInf
        }
        catch {
            Show-WriteErrorMessage -Ui $ui -ErrorText $_.Exception.Message
            return
        }

        $diffPair = Get-DiffIndexPair -ScriptRoot $PSScriptRoot -LiveSecEditInfPath $liveSecEditInfPath -ImportSecEditInfPath $importFiles.SecEditInfPath -LiveAuditCsvPath $script:RealAuditCsvPath -ImportAuditCsvPath $importFiles.AuditCsvPath

        $checkedRemoval = @()
        $uncheckedChange = @()
        $policiesById = @{}
        foreach ($p in $script:admxIndex.policies) { $policiesById[$p.id] = $p }

        # Full Change/Add diff, computed regardless of mode: Standard mode
        # only ever reviews Security-Options removals (via
        # Get-SecurityOptionsRemovalCandidates below), but every other diffed
        # setting is still applied wholesale from the import file, so this is
        # also the authoritative "what actually changed" list used to log
        # every imported parameter with its value (see the log loop after a
        # successful apply, below).
        $liveMachineLookup = New-PolLookup -Entries (Get-LiveMachinePolEntries)
        $liveUserLookup = New-PolLookup -Entries (Get-LiveUserPolEntries)
        $importMachineEntries = Read-PolFile -Path $importFiles.MachinePolPath
        $importUserEntries = Read-PolFile -Path $importFiles.UserPolPath
        $importMachineLookup = New-PolLookup -Entries $importMachineEntries
        $importUserLookup = New-PolLookup -Entries $importUserEntries

        $secRows = Get-GranularSecurityDiffRows -DiffIndexPair $diffPair -Ui $ui
        $audRows = Get-GranularAuditDiffRows -DiffIndexPair $diffPair -Ui $ui
        $admxRows = Get-GranularAdmxDiffRows -LiveMachineLookup $liveMachineLookup -LiveUserLookup $liveUserLookup -ImportMachineLookup $importMachineLookup -ImportUserLookup $importUserLookup -Ui $ui

        # .ToArray(), not @() - $secRows.Change/etc. are List[object]
        # properties, and @() wrapping an existing List[object] variable
        # directly (not through a pipeline) throws ArgumentException on
        # this machine (PowerShell 5.1 dynamic-binder quirk, see
        # PolicyWriter.ps1-adjacent lessons elsewhere in this project).
        $allChangeRows = $secRows.Change.ToArray() + $audRows.Change.ToArray() + $admxRows.Change.ToArray()
        $allAddRows = $secRows.Add.ToArray() + $audRows.Add.ToArray() + $admxRows.Add.ToArray()

        if ($mode -eq 'Standard') {
            $candidates = Get-SecurityOptionsRemovalCandidates -DiffIndexPair $diffPair -Ui $ui
            if ($candidates.Count -gt 0) {
                $result = Show-ImportConfirmationDialog -Owner $window -ScriptRoot $PSScriptRoot -Ui $ui -ChangeRows $candidates -AddRows @()
                if (-not $result) { return }
                $checkedRemoval = @($result.ChangeRows | Where-Object { $_.IsSelected })
                $uncheckedChange = @($result.ChangeRows | Where-Object { -not $_.IsSelected })
            }
        }
        else {
            $result = Show-ImportConfirmationDialog -Owner $window -ScriptRoot $PSScriptRoot -Ui $ui -ChangeRows $allChangeRows -AddRows $allAddRows
            if (-not $result) { return }
            $checkedRemoval = @($result.ChangeRows | Where-Object { $_.IsSelected })
            $uncheckedChange = @($result.ChangeRows | Where-Object { -not $_.IsSelected })
        }

        $backupDir = Backup-LiveGpoFilesForImport -LiveSecEditInfPath $liveSecEditInfPath
        $applySucceeded = $false

        # Busy cursor + overlay while the real apply runs (secedit /configure
        # + registry.pol/audit.csv writes, can take several seconds) - same
        # visual mechanism as Invoke-CisIndexRebuild (OptionsDialog.ps1,
        # Add/Delete audit file): MainBusyOverlay (see
        # AllWindows.Reference.xaml) grays out the main window,
        # Mouse.OverrideCursor also forces the wait cursor everywhere (more
        # reliable than Window.Cursor alone, which only refreshes on the next
        # mouse move and gets overridden by some controls' own cursor). The
        # Dispatcher.Invoke forces a render pass BEFORE the blocking calls
        # below, otherwise WPF only paints either one after the fact.
        $mainBusyOverlay = $window.FindName('MainBusyOverlay')
        $window.FindName('MainBusyOverlayLabel').Text = $ui.ImportBusyOverlayLabel
        $mainBusyOverlay.Visibility = 'Visible'
        [System.Windows.Input.Mouse]::OverrideCursor = [System.Windows.Input.Cursors]::Wait
        $window.Dispatcher.Invoke([action]{}, [System.Windows.Threading.DispatcherPriority]::Render) | Out-Null
        try {
            $importGpt = Read-GptTmplInf -Path $importFiles.SecEditInfPath
            $secCatalog = Get-SecurityCatalogEntries
            $secSettingsById = @{}
            foreach ($e in $secCatalog) { $secSettingsById["$($e.section)::$($e.name)"] = $e }

            Restore-UncheckedSecurityRowsToImportGpt -ImportGpt $importGpt -UncheckedRows @(@($uncheckedChange) | Where-Object { $_.Kind -eq 'Security' }) -SettingsById $secSettingsById | Out-Null

            $baselineKeys = Get-RegistryValuesBaselineKeysForImport -CheckedRemovalRows @(@($checkedRemoval) | Where-Object { $_.Kind -eq 'Security' })
            $secResult = Invoke-ImportSecEditApply -ImportGpt $importGpt -RegistryValuesBaselineKeys $baselineKeys
            if ($secResult.ExitCode -ne 0) { throw $secResult.Output }

            if ($mode -eq 'Granular') {
                $mergedMachine = Restore-UncheckedAdmxRowsToImportEntries -ImportEntries $importMachineEntries -UncheckedRows @(@($uncheckedChange) | Where-Object { $_.Kind -eq 'Admx' }) -Scope 'Machine' -PoliciesById $policiesById -LiveLookup $liveMachineLookup
                $mergedUser = Restore-UncheckedAdmxRowsToImportEntries -ImportEntries $importUserEntries -UncheckedRows @(@($uncheckedChange) | Where-Object { $_.Kind -eq 'Admx' }) -Scope 'User' -PoliciesById $policiesById -LiveLookup $liveUserLookup
            }
            else {
                $mergedMachine = Read-PolFile -Path $importFiles.MachinePolPath
                $mergedUser = Read-PolFile -Path $importFiles.UserPolPath
            }
            $admxResult = Invoke-ImportAdmxApply -MachineEntries $mergedMachine -UserEntries $mergedUser
            if ($admxResult.ExitCode -ne 0) { throw $admxResult.Output }

            $importAuditRows = Read-AuditCsv -Path $importFiles.AuditCsvPath
            if ($mode -eq 'Granular') {
                Restore-UncheckedAuditRowsToImportRows -ImportRows $importAuditRows -UncheckedRows @(@($uncheckedChange) | Where-Object { $_.Kind -eq 'AdvancedAudit' }) -LiveRows (Get-LiveAuditCsvRows)
            }
            $audResult = Invoke-ImportAuditCsvApply -MergedRows $importAuditRows
            if ($audResult.ExitCode -ne 0) { throw $audResult.Output }

            # Point of no return: all 3 real writes succeeded. The backup is
            # kept on disk (per the user's request, so a pre-import snapshot
            # always remains available) - only clear $backupDir so anything
            # that fails from here on (e.g. refreshing the on-screen list)
            # can never trigger the catch below into rolling back writes that
            # already succeeded.
            $backupDir = $null
            $applySucceeded = $true
        }
        catch {
            $failureText = "$($_.Exception.Message)`r`n`r`n[DEBUG] $($_.InvocationInfo.PositionMessage)`r`n$($_.ScriptStackTrace)"
            if ($backupDir) {
                $rollback = Restore-LiveGpoFilesFromImportBackup -BackupDir $backupDir
                if ($rollback.Success) {
                    [System.Windows.MessageBox]::Show(($ui.ImportFailedRolledBackMessage -f $failureText), $ui.WriteErrorTitle, 'OK', 'Error') | Out-Null
                }
                else {
                    [System.Windows.MessageBox]::Show(($ui.ImportFailedRollbackFailedMessage -f $failureText, $rollback.Error, $backupDir), $ui.WriteErrorTitle, 'OK', 'Error') | Out-Null
                }
            }
            else {
                Show-WriteErrorMessage -Ui $ui -ErrorText $failureText
            }
        }
        finally {
            [System.Windows.Input.Mouse]::OverrideCursor = $null
            $mainBusyOverlay.Visibility = 'Collapsed'
        }

        if ($applySucceeded) {
            # Best-effort only from here: the real import already succeeded,
            # so a failure refreshing the app's own on-screen cache must not
            # be reported as an import failure (and must never trigger a
            # rollback of writes that already succeeded).
            try {
                if (-not $script:ActiveProject) {
                    # The app's own secedit.inf cache (see
                    # plan-gpedit-security-secedit-cycle.md) is not the real
                    # machine and was not touched by the import apply above -
                    # re-export it now so the on-screen list reflects the
                    # just-applied real state immediately, not only after the
                    # next launch.
                    Invoke-SecEditInfExport -SecEditInfPath $script:SecEditInfPath | Out-Null
                    Update-GpoDerivedState
                }
            }
            catch {
                # Swallowed on purpose - see comment above.
            }
            # Log every parameter actually applied by this import, with its
            # old/new value - $allChangeRows/$allAddRows is the full diff
            # (all modes), minus whatever the user left unchecked in the
            # confirmation dialog (kept at its live value, so not imported).
            $uncheckedKeys = @{}
            foreach ($r in $uncheckedChange) { $uncheckedKeys["$($r.Kind)|$($r.Id)"] = $true }
            $appliedRows = @(@($allChangeRows) + @($allAddRows) | Where-Object { -not $uncheckedKeys.ContainsKey("$($_.Kind)|$($_.Id)") })
            $importedProjectName = [System.IO.Path]::GetFileNameWithoutExtension($manifestPath)
            Write-GpEditImportStartLog -ProjectName $importedProjectName
            foreach ($row in $appliedRows) {
                Write-GpEditSettingChangeLog -ParameterName $row.Name -Key $row.Id -OldValue $row.CurrentState -NewValue $row.ImportState
            }

            Write-GpEditProjectLog -Action 'Imported' -ProjectName $importedProjectName
            [System.Windows.MessageBox]::Show($ui.ImportSuccessMessage, $ui.InfoTitle, 'OK', 'Information') | Out-Null
        }
    }
    finally {
        if ($liveSecEditInfPath -and (Test-Path -LiteralPath $liveSecEditInfPath)) {
            Remove-Item -LiteralPath $liveSecEditInfPath -Force -ErrorAction SilentlyContinue
        }
    }
}
