<#
    Step 3 - Static catalog of local security settings in scope: Password
    Policy, Account Lockout Policy, Audit Policy, User Rights Assignment,
    basic Security Options. Unlike Administrative Templates (ADMX/ADML),
    these settings aren't self-describing - gpedit.msc hardcodes their
    names/descriptions itself, hence this catalog. English only (en-US) -
    the app no longer has a language selector.
#>

Set-StrictMode -Version Latest

# "Live catalog editor" feature (Name/Explain/CIS Info editable from the UI,
# see plan-gpedit-security-catalog-editor.md): single switch - setting to
# $false disables editing entirely (pencil buttons hidden in EditDialogs.ps1)
# without touching the rest of the code or losing already-saved edits.
#
# Driven by the "Editor Mode" setting in File > Options (persisted in
# settings.json, see AppSettings.ps1/OptionsDialog.ps1), applied at
# GpEdit.ps1 startup. This file is re-dot-sourced on every successful edit
# (see Show-SecurityEditDialog, EditDialogs.ps1): only assign $true if the
# variable doesn't exist yet, otherwise the user's "Editor Mode" choice
# would be silently wiped on the first edit of the session.
if (-not (Test-Path variable:script:CatalogEditingEnabled)) {
    $script:CatalogEditingEnabled = $true
}

# No pre-declaration here either (same reason as $CatalogEditingEnabled
# above): re-dot-sourcing on every edit would re-run it and wipe the
# "already saved this session" state. Initialized via Get-Variable
# (no error if absent) in Set-SecurityCatalogEntryField instead.


# --- Catalog data (Data_SecurityCatalog.json) -------------------------------
# The 6 catalogs below (Password/Lockout/System Access/Registry Values/Audit/
# User Rights) used to be literal PowerShell hashtables in this file. They
# now live in a Data_SecurityCatalog.json (one array per catalog, each entry
# carrying its original "Key" plus the same fields as before) so the data can
# be reviewed/diffed independently of the app logic. This file rebuilds the
# exact same $script:<Name>Catalog ordered-hashtable shape the rest of this
# file expects (.Keys/.ContainsKey/dot access all still work), so
# Get-SecurityCatalogEntries and Set-SecurityCatalogEntryField below did not
# need to change.
#
# This file is re-dot-sourced after every live edit (see Show-SecurityEditDialog,
# EditDialogs.ps1) to reload the hashtables in memory - only set a default
# here if not already set (same guard as $CatalogEditingEnabled above),
# otherwise that re-dot-source would silently undo the real, writable
# location GpEdit.ps1 points this at after loading File > Options settings
# (indexDir, configurable) in favor of this repo-bundled fallback (only
# actually reached if this file is dot-sourced outside of GpEdit.ps1, e.g. a
# standalone test harness).
if (-not (Test-Path variable:script:SecurityCatalogDataPath)) {
    $script:SecurityCatalogDataPath = Join-Path $PSScriptRoot '..\DefaultData\Data_SecurityCatalog.json'
}

function ConvertTo-SecurityCatalogHashtable {
    param($Entries)
    $result = [ordered]@{}
    foreach ($e in $Entries) {
        $fields = @{}
        foreach ($prop in $e.PSObject.Properties) {
            if ($prop.Name -eq 'Key') { continue }
            $val = $prop.Value
            if ($prop.Name -in @('Choices', 'Flags') -and $val) {
                $val = @($val | ForEach-Object { @{ Value = $_.Value; DisplayName = $_.DisplayName } })
            }
            $fields[$prop.Name] = $val
        }
        $result[$e.Key] = $fields
    }
    return $result
}

function Import-SecurityCatalogData {
    # (Re)loads the 6 catalogs from disk - called once below, and again by
    # every Set-SecurityCatalogEntryField caller re-dot-sourcing this file
    # after an edit (see EditDialogs.ps1), so in-memory data always reflects
    # what was just written to Data_SecurityCatalog.json.
    $raw = Get-Content -Raw -Encoding UTF8 -LiteralPath $script:SecurityCatalogDataPath | ConvertFrom-Json

    $script:PasswordPolicyCatalog          = ConvertTo-SecurityCatalogHashtable -Entries $raw.PasswordPolicyCatalog
    $script:AccountLockoutPolicyCatalog    = ConvertTo-SecurityCatalogHashtable -Entries $raw.AccountLockoutPolicyCatalog
    $script:OtherSystemAccessCatalog       = ConvertTo-SecurityCatalogHashtable -Entries $raw.OtherSystemAccessCatalog
    $script:SecurityOptionsRegistryCatalog = ConvertTo-SecurityCatalogHashtable -Entries $raw.SecurityOptionsRegistryCatalog
    $script:AuditPolicyCatalog             = ConvertTo-SecurityCatalogHashtable -Entries $raw.AuditPolicyCatalog
    $script:UserRightsCatalog              = ConvertTo-SecurityCatalogHashtable -Entries $raw.UserRightsCatalog
}

Import-SecurityCatalogData

# Category/section (as exposed by Get-SecurityCatalogEntries) -> source
# $script:<...>Catalog variable name - stable mapping, one entry per
# catalog hashtable above.
$script:SecurityCatalogVariableByCategorySection = @(
    @{ Category = 'Password Policy'; Section = 'System Access'; Variable = 'PasswordPolicyCatalog' }
    @{ Category = 'Account Lockout Policy'; Section = 'System Access'; Variable = 'AccountLockoutPolicyCatalog' }
    @{ Category = 'Security Options'; Section = 'System Access'; Variable = 'OtherSystemAccessCatalog' }
    @{ Category = 'Security Options'; Section = 'Registry Values'; Variable = 'SecurityOptionsRegistryCatalog' }
    @{ Category = 'Audit Policy'; Section = 'Event Audit'; Variable = 'AuditPolicyCatalog' }
    @{ Category = 'User Rights Assignment'; Section = 'Privilege Rights'; Variable = 'UserRightsCatalog' }
)

function Get-SecurityCatalogVariableName {
    param([string]$Category, [string]$Section)
    $match = $script:SecurityCatalogVariableByCategorySection | Where-Object { $_.Category -eq $Category -and $_.Section -eq $Section } | Select-Object -First 1
    if (-not $match) { return $null }
    return $match.Variable
}

# --- Live catalog editor (Name/Explain) -------------------------------------
# See plan-gpedit-security-catalog-editor.md. Edits the entry directly in
# Data_SecurityCatalog.json (read, modify the one field in memory, re-write)
# instead of the PowerShell-source AST surgery this used to require when the
# same data lived as literal hashtables in this .ps1 file.
# ---------------------------------------------------------------------------

function Set-SecurityCatalogEntryField {
    <#
        Updates one entry's DisplayName/Explain field in
        Data_SecurityCatalog.json and writes the result back to disk. $Path
        is the caller's SecurityCatalog.ps1 path (kept for call-site
        compatibility) but otherwise unused - the real JSON file is
        $script:SecurityCatalogDataPath, NOT a path derived from $Path
        (that used to resolve one level too shallow - see bug report).
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$CatalogKey,
        [Parameter(Mandatory)][ValidateSet('DisplayName', 'Explain')][string]$Field,
        [Parameter(Mandatory)][string]$Text
    )

    $catalogVar = Get-SecurityCatalogVariableName -Category $Category -Section $Section
    if (-not $catalogVar) { throw "Unknown category/section: $Category / $Section" }

    $jsonPath = $script:SecurityCatalogDataPath
    $data = Get-Content -Raw -Encoding UTF8 -LiteralPath $jsonPath | ConvertFrom-Json

    $catalogArray = $data.$catalogVar
    if ($null -eq $catalogArray) { throw "Catalog not found: $catalogVar" }

    $entry = $catalogArray | Where-Object { $_.Key -eq $CatalogKey } | Select-Object -First 1
    if (-not $entry) { throw "Entry not found: $CatalogKey in $catalogVar" }

    if ($entry.PSObject.Properties[$Field]) {
        $entry.$Field = $Text
    }
    else {
        $entry | Add-Member -MemberType NoteProperty -Name $Field -Value $Text
    }

    $json = $data | ConvertTo-Json -Depth 10
    $utf8Bom = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllText($jsonPath, $json, $utf8Bom)
}

function Get-CatalogExplainText {
    # Full "Explain" text; absent from $c.Explain until sourced from
    # official Microsoft docs, so falls back to the short description
    # instead of leaving the tab empty.
    param($Entry, [string]$FallbackDescription)
    if ($Entry.ContainsKey('Explain') -and $Entry.Explain) {
        return $Entry.Explain
    }
    return $FallbackDescription
}

function Get-SecurityCatalogEntries {
    # Flattens the catalogs above into one list (Category, Name, DisplayName,
    # Description, ValueType) for indexing/search (Step 7), same shape as ADMX policies.
    $list = New-Object System.Collections.Generic.List[object]

    foreach ($key in $script:PasswordPolicyCatalog.Keys) {
        $c = $script:PasswordPolicyCatalog[$key]
        $description = $c.Description
        $list.Add([ordered]@{ category = 'Password Policy'; section = 'System Access'; name = $key; catalogKey = $key; displayName = $c.DisplayName; description = $description; explain = (Get-CatalogExplainText -Entry $c -FallbackDescription $description); valueType = $c.ValueType; regType = $null; choices = $null; flags = $null; alwaysConfigured = $false })
    }
    foreach ($key in $script:AccountLockoutPolicyCatalog.Keys) {
        $c = $script:AccountLockoutPolicyCatalog[$key]
        $description = $c.Description
        $list.Add([ordered]@{ category = 'Account Lockout Policy'; section = 'System Access'; name = $key; catalogKey = $key; displayName = $c.DisplayName; description = $description; explain = (Get-CatalogExplainText -Entry $c -FallbackDescription $description); valueType = $c.ValueType; regType = $null; choices = $null; flags = $null; alwaysConfigured = $false })
    }
    foreach ($key in $script:OtherSystemAccessCatalog.Keys) {
        $c = $script:OtherSystemAccessCatalog[$key]
        $description = $c.Description
        $list.Add([ordered]@{ category = 'Security Options'; section = 'System Access'; name = $key; catalogKey = $key; displayName = $c.DisplayName; description = $description; explain = (Get-CatalogExplainText -Entry $c -FallbackDescription $description); valueType = $c.ValueType; regType = $null; choices = $null; flags = $null; alwaysConfigured = $false })
    }
    foreach ($key in $script:SecurityOptionsRegistryCatalog.Keys) {
        $c = $script:SecurityOptionsRegistryCatalog[$key]
        $choices = $null
        if ($c.ContainsKey('Choices')) {
            $choices = @($c.Choices | ForEach-Object { [ordered]@{ value = $_.Value; displayName = $_.DisplayName } })
        }
        $flags = $null
        if ($c.ContainsKey('Flags')) {
            $flags = @($c.Flags | ForEach-Object { [ordered]@{ value = $_.Value; displayName = $_.DisplayName } })
        }
        $regType = if ($c.ContainsKey('RegType')) { $c.RegType } else { $null }
        $alwaysConfigured = if ($c.ContainsKey('AlwaysConfigured')) { $c.AlwaysConfigured } else { $false }
        $description = $c.Description
        $list.Add([ordered]@{
            category    = 'Security Options'
            section     = 'Registry Values'
            name        = "MACHINE\$($c.RegistryPath)\$($c.ValueName)"
            catalogKey  = $key
            displayName = $c.DisplayName
            description = $description
            explain     = (Get-CatalogExplainText -Entry $c -FallbackDescription $description)
            valueType   = $c.ValueType
            regType     = $regType
            choices     = $choices
            flags       = $flags
            alwaysConfigured = $alwaysConfigured
        })
    }
    foreach ($key in $script:AuditPolicyCatalog.Keys) {
        $c = $script:AuditPolicyCatalog[$key]
        $description = $c.Description
        $list.Add([ordered]@{ category = 'Audit Policy'; section = 'Event Audit'; name = $key; catalogKey = $key; displayName = $c.DisplayName; description = $description; explain = (Get-CatalogExplainText -Entry $c -FallbackDescription $description); valueType = $c.ValueType; regType = $null; choices = $null; flags = $null; alwaysConfigured = $false })
    }
    foreach ($key in $script:UserRightsCatalog.Keys) {
        $c = $script:UserRightsCatalog[$key]
        $list.Add([ordered]@{ category = 'User Rights Assignment'; section = 'Privilege Rights'; name = $key; catalogKey = $key; displayName = $c.DisplayName; description = ''; explain = (Get-CatalogExplainText -Entry $c -FallbackDescription ''); valueType = 'principal-list'; regType = $null; choices = $null; flags = $null; alwaysConfigured = $false })
    }

    return $list
}