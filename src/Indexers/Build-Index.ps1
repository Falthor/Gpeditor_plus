<#
    Single entry point for every JSON index the app caches under indexDir.
    Replaces the four former New-AdmxIndex/New-SecurityIndex/
    New-AdvancedAuditIndex/New-CisIndex scripts; -Kind selects which one
    to build:

      Admx          .admx/.adml under PolicyDefinitions      -> admx-index.json
      Security      SecurityCatalog + live secedit.inf       -> security-index.json
      AdvancedAudit AdvancedAuditCatalog + live audit.csv    -> advanced-audit-index.json
      Cis           CIS .audit files (Tenable Nessus format) -> cis-index.json

    Deliberately still a standalone script invoked with "&" (never
    dot-sourced): each run gets its own scope, so the per-kind strict mode
    below and the indexing state cannot leak into - or collide with - the
    caller's variables (GpEdit.ps1 already has a $script:categoriesById, and
    PowerShell variable names are case-insensitive).

    Cache policy, unchanged per kind: Admx and Cis are rebuilt only when
    their source fingerprint changed (-SourceFingerprint, stored in
    meta.sourceFingerprint and compared by the caller); Security and
    AdvancedAudit are cheap and always rebuilt, so the UI never shows stale
    state.
#>
param(
    [Parameter(Mandatory)]
    [ValidateSet('Admx', 'Security', 'AdvancedAudit', 'Cis')]
    [string]$Kind,

    # Defaults to data\<kind>-index.json when omitted (see below).
    [string]$OutputPath = '',

    # --- Admx ---
    [string]$PolicyDefinitionsPath = (Join-Path $env:WinDir 'PolicyDefinitions'),
    [string]$Language = 'en-US',
    [string]$FallbackLanguage = 'en-US',

    # --- Security ---
    [string]$SecEditInfPath = (Join-Path $PSScriptRoot '..\..\data\secedit.inf'),

    # --- AdvancedAudit ---
    [string]$AuditCsvPath = (Join-Path $env:WinDir 'System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv'),

    # --- Cis ---
    [string]$AuditFilesPath = (Join-Path $PSScriptRoot '..\..\Audit file'),

    # Fingerprint of the source folder (PolicyDefinitionsFingerprint.ps1 /
    # AuditFilesFingerprint.ps1), stored in meta.sourceFingerprint so the
    # caller can detect a stale cache without re-scanning files here.
    # Only used by -Kind Admx and -Kind Cis.
    [string]$SourceFingerprint = ''
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

function Write-IndexFile {
    # Single write tail for all four indexes: create the target folder if
    # needed, then serialize. Out-File -Encoding utf8 is UTF-8 *with* BOM on
    # Windows PowerShell 5.1, which is what every reader in the app expects
    # (Get-Content -Raw -Encoding UTF8) - do not "modernize" this.
    param(
        [Parameter(Mandatory)]$Index,
        [Parameter(Mandatory)][string]$Path,
        [int]$Depth = 10,
        [switch]$Compress
    )

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $json = if ($Compress) { $Index | ConvertTo-Json -Depth $Depth -Compress } else { $Index | ConvertTo-Json -Depth $Depth }
    $json | Out-File -LiteralPath $Path -Encoding utf8
}

# ###########################################################################
# ADMX / ADML indexer
# ###########################################################################

function New-AdmxIndexState {    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ($PSCmdlet.ShouldProcess('New-AdmxIndexState', 'Invoke')) {
    # All state for one ADMX indexing run, passed explicitly instead of
    # living in $script: globals (see the header note on scope collisions).
    return @{
        CategoriesById   = @{}   # id -> ordered hashtable
        SupportedOnById  = @{}   # id -> already-resolved display text
        Policies         = New-Object System.Collections.Generic.List[object]
        # .admx files excluded from the index for lack of an .adml, in the
        # requested language AND the fallback - see
        # plan-gpedit-ui-enhancements.md §1.
        SkippedAdmxFiles = New-Object System.Collections.Generic.List[string]
    }

    }
}

function Get-AdmlStringMap {
    # Flattens an .adml <stringTable> into id -> localized text.
    param([xml]$AdmlXml)

    $map = @{}
    if ($null -eq $AdmlXml) { return $map }
    $stringTable = $AdmlXml.policyDefinitionResources.resources.stringTable
    if ($null -eq $stringTable) { return $map }
    foreach ($s in @($stringTable.string)) {
        if ($null -ne $s -and $s.id) { $map[$s.id] = $s.'#text' }
    }
    return $map
}

function Get-AdmlPresentationLabelMap {
    <#
        For a given policy (presentation="$(presentation.XXX)"), extracts the
        localized label of each presentation element from the .adml. Key is
        refId (matches the ADMX element id), value is the label text.

        Two forms depending on control type: <textBox> has text in a child
        <label> node; all others (<decimalTextBox>, <dropdownList>,
        <comboBox>, <checkBox>, <listBox>, <multiTextBox>...) have text
        directly in the node itself.

        Without this, the UI would only have the raw ADMX id (e.g.
        "RA_Options_Share_Control_Message") to show as field label - see
        plan-gpedit-search-v2.md §13.
    #>
    param([string]$PresentationRef, [xml]$AdmlXml)

    $map = @{}
    if ([string]::IsNullOrEmpty($PresentationRef) -or $null -eq $AdmlXml) { return $map }

    $refMatch = [regex]::Match($PresentationRef, '^\$\(presentation\.([A-Za-z0-9_\.]+)\)$')
    if (-not $refMatch.Success) { return $map }
    $presentationId = $refMatch.Groups[1].Value

    $presentationTable = $AdmlXml.policyDefinitionResources.resources.presentationTable
    if ($null -eq $presentationTable) { return $map }
    $presentation = @($presentationTable.presentation) | Where-Object { $_.id -eq $presentationId } | Select-Object -First 1
    if ($null -eq $presentation) { return $map }

    foreach ($control in $presentation.ChildNodes) {
        if ($control.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
        if (-not $control.refId) { continue }
        # The dynamic .label shortcut (lookup by LocalName - reliable even
        # with a default XML namespace on the root, unlike
        # SelectSingleNode('label') without an XmlNamespaceManager) can return
        # either a string or the <label> XmlElement itself depending on node
        # shape, so normalize explicitly instead of blindly calling .Trim()
        # (a direct call used to break parsing of appv.adml).
        $raw = if ($control.LocalName -eq 'textBox') { $control.label } else { $control.InnerText }
        $label = if ($raw -is [System.Xml.XmlElement]) { $raw.InnerText } elseif ($raw -is [string]) { $raw } else { $null }
        if ($label) { $map[$control.refId] = $label.Trim() }
    }
    return $map
}

function Expand-AdmlText {
    # Replaces every "$(string.xxx)" reference by its localized text.
    # "$(presentation.xxx)" references are left as-is on purpose: they are
    # resolved separately by Get-AdmlPresentationLabelMap.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'StringMap', Justification = 'Used inside the $evaluator scriptblock passed as a MatchEvaluator delegate, invisible to this analyzer rule.')]
    param([string]$Value, [hashtable]$StringMap)

    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    $evaluator = {
        param($m)
        $kind = $m.Groups[1].Value
        $key = $m.Groups[2].Value
        if ($kind -eq 'string' -and $StringMap.ContainsKey($key)) { return $StringMap[$key] }
        return $m.Value
    }
    return [regex]::Replace($Value, '\$\((string|presentation)\.([A-Za-z0-9_\.]+)\)', [System.Text.RegularExpressions.MatchEvaluator]$evaluator)
}

function Get-AdmxPolicyValue {
    # Extracts a value (decimal or string) from a node such as
    # <enabledValue><decimal value="1"/></enabledValue> or
    # <item><value><string>...</string></value></item>.
    param($Node)

    if ($null -eq $Node) { return $null }
    if ($Node.decimal) {
        $raw = $Node.decimal.value
        $parsed = 0
        if ([int]::TryParse($raw, [ref]$parsed)) { return $parsed }
        return $raw
    }
    if ($Node.string -is [string]) { return $Node.string }
    if ($Node.value) { return Get-AdmxPolicyValue $Node.value }
    return $null
}

function New-AdmxPrefixMap {
    # Maps every namespace prefix this .admx can reference (its own target
    # prefix plus each <using>) to the full namespace.
        [CmdletBinding(SupportsShouldProcess)]
    param($PolicyNamespaces, [string]$OwnPrefix, [string]$OwnNamespace)
    if ($PSCmdlet.ShouldProcess('New-AdmxPrefixMap', 'Invoke')) {

    $map = @{}
    if ($OwnPrefix) { $map[$OwnPrefix] = $OwnNamespace }
    if ($null -ne $PolicyNamespaces -and $PolicyNamespaces.using) {
        foreach ($u in @($PolicyNamespaces.using)) {
            if ($u.prefix -and $u.namespace) { $map[$u.prefix] = $u.namespace }
        }
    }
    return $map

    }
}

function Resolve-AdmxRef {
    # Converts a "prefix:name" or bare "name" reference into the globally
    # unique id "namespace::name" used as key throughout the index.
    param([string]$Ref, [hashtable]$PrefixMap, [string]$CurrentNamespace)

    if ([string]::IsNullOrEmpty($Ref)) { return $null }
    if ($Ref -match '^(?<p>[^:]+):(?<n>.+)$') {
        $p = $Matches['p']
        $n = $Matches['n']
        if ($PrefixMap.ContainsKey($p)) { return "$($PrefixMap[$p])::$n" }
        return "$($p)::$n"
    }
    return "$CurrentNamespace::$Ref"
}

function Convert-AdmxElement {
    # Turns one <elements> child (the sub-settings shown when a policy is
    # Enabled) into its indexed shape, with the type-specific extras the edit
    # dialog needs to build the right control.
    param($ElementNode, [hashtable]$StringMap, [hashtable]$PresentationLabels = @{})

    $item = [ordered]@{
        type      = $ElementNode.LocalName
        id        = $ElementNode.id
        key       = $ElementNode.key
        valueName = $ElementNode.valueName
        required  = ($ElementNode.required -eq 'true')
        # Localized label from the ADML presentation (see
        # Get-AdmlPresentationLabelMap); $null if absent, in which case the
        # UI falls back to the raw id (EditDialogs.ps1).
        label     = if ($PresentationLabels.ContainsKey($ElementNode.id)) { $PresentationLabels[$ElementNode.id] } else { $null }
    }

    switch ($ElementNode.LocalName) {
        'decimal' {
            $item.minValue     = $ElementNode.minValue
            $item.maxValue     = $ElementNode.maxValue
            $item.defaultValue = $ElementNode.defaultValue
            $item.storeAsText  = ($ElementNode.storeAsText -eq 'true')
        }
        'text' {
            $item.maxLength    = $ElementNode.maxLength
            $item.defaultValue = $ElementNode.defaultValue
            $item.expandable   = ($ElementNode.expandable -eq 'true')
        }
        'multiText' {
            $item.maxLength  = $ElementNode.maxLength
            $item.maxStrings = $ElementNode.maxStrings
        }
        'boolean' {
            # Present with $null rather than omitted when the ADMX doesn't
            # define one (a boolean element isn't required to have both) -
            # every element shares the same shape under the app's
            # Set-StrictMode -Version Latest, where a missing property
            # throws but a $null one does not (PolicyWriter.ps1 checks both).
            $item.trueValue  = if ($ElementNode.trueValue)  { Get-AdmxPolicyValue $ElementNode.trueValue }  else { $null }
            $item.falseValue = if ($ElementNode.falseValue) { Get-AdmxPolicyValue $ElementNode.falseValue } else { $null }
        }
        'enum' {
            $enumItems = New-Object System.Collections.Generic.List[object]
            foreach ($it in @($ElementNode.item)) {
                if ($null -eq $it) { continue }
                $enumItems.Add([ordered]@{
                    displayName = Expand-AdmlText -Value $it.displayName -StringMap $StringMap
                    value       = Get-AdmxPolicyValue $it.value
                })
            }
            $item.items = $enumItems
        }
        'list' {
            $item.explicitValue = ($ElementNode.explicitValue -eq 'true')
            $item.additive      = ($ElementNode.additive -eq 'true')
        }
    }
    return $item
}

function Import-AdmxFile {
    # Reads one .admx plus its .adml translation and appends its
    # supportedOn definitions, categories and policies to $State.
    param(
        [hashtable]$State,
        [System.IO.FileInfo]$AdmxFile,
        [string]$PolicyDefinitionsPath,
        [string]$Language,
        [string]$FallbackLanguage
    )

    [xml]$admx = Get-Content -LiteralPath $AdmxFile.FullName -Raw -Encoding UTF8

    $pd = $admx.policyDefinitions
    if ($null -eq $pd) { return }

    $targetNs     = $pd.policyNamespaces.target.namespace
    $targetPrefix = $pd.policyNamespaces.target.prefix
    if (-not $targetNs) { $targetNs = $AdmxFile.BaseName }

    $prefixMap = New-AdmxPrefixMap -PolicyNamespaces $pd.policyNamespaces -OwnPrefix $targetPrefix -OwnNamespace $targetNs

    # --- Matching .adml: requested language first, then fallback ---
    $admlPath = Join-Path (Join-Path $PolicyDefinitionsPath $Language) ($AdmxFile.BaseName + '.adml')
    if (-not (Test-Path -LiteralPath $admlPath)) {
        $admlPath = Join-Path (Join-Path $PolicyDefinitionsPath $FallbackLanguage) ($AdmxFile.BaseName + '.adml')
    }
    if (-not (Test-Path -LiteralPath $admlPath)) {
        # No .adml either way: exclude this .admx entirely rather than index
        # unresolved raw labels (potentially unreadable "$(string.xxx)"
        # keys) - see plan-gpedit-ui-enhancements.md §1.
        $State.SkippedAdmxFiles.Add($AdmxFile.Name)
        return
    }
    [xml]$adml = Get-Content -LiteralPath $admlPath -Raw -Encoding UTF8
    $stringMap = Get-AdmlStringMap -AdmlXml $adml

    # --- supportedOn definitions (resolved to text right away) ---
    if ($pd.supportedOn -and $pd.supportedOn.definitions -and $pd.supportedOn.definitions.definition) {
        foreach ($def in @($pd.supportedOn.definitions.definition)) {
            $State.SupportedOnById["$targetNs::$($def.name)"] = Expand-AdmlText -Value $def.displayName -StringMap $stringMap
        }
    }

    # --- categories (the tree nodes) ---
    if ($pd.categories -and $pd.categories.category) {
        foreach ($cat in @($pd.categories.category)) {
            $id = "$targetNs::$($cat.name)"
            $parentId = $null
            if ($cat.parentCategory -and $cat.parentCategory.ref) {
                $parentId = Resolve-AdmxRef -Ref $cat.parentCategory.ref -PrefixMap $prefixMap -CurrentNamespace $targetNs
            }
            $State.CategoriesById[$id] = [ordered]@{
                id          = $id
                name        = $cat.name
                namespace   = $targetNs
                displayName = Expand-AdmlText -Value $cat.displayName -StringMap $stringMap
                parentId    = $parentId
            }
        }
    }

    # --- policies (the settings themselves) ---
    if ($pd.policies -and $pd.policies.policy) {
        foreach ($pol in @($pd.policies.policy)) {
            $categoryId = $null
            if ($pol.parentCategory -and $pol.parentCategory.ref) {
                $categoryId = Resolve-AdmxRef -Ref $pol.parentCategory.ref -PrefixMap $prefixMap -CurrentNamespace $targetNs
            }
            $supportedOnId = $null
            if ($pol.supportedOn -and $pol.supportedOn.ref) {
                $supportedOnId = Resolve-AdmxRef -Ref $pol.supportedOn.ref -PrefixMap $prefixMap -CurrentNamespace $targetNs
            }

            $elements = New-Object System.Collections.Generic.List[object]
            if ($pol.elements) {
                $presentationLabels = Get-AdmlPresentationLabelMap -PresentationRef $pol.presentation -AdmlXml $adml
                foreach ($el in $pol.elements.ChildNodes) {
                    if ($el.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
                    $elements.Add((Convert-AdmxElement -ElementNode $el -StringMap $stringMap -PresentationLabels $presentationLabels))
                }
            }

            $State.Policies.Add([ordered]@{
                id             = "$targetNs::$($pol.name)"
                name           = $pol.name
                namespace      = $targetNs
                admxFile       = $AdmxFile.Name
                class          = $pol.class
                displayName    = Expand-AdmlText -Value $pol.displayName -StringMap $stringMap
                explainText    = Expand-AdmlText -Value $pol.explainText -StringMap $stringMap
                registryKey    = $pol.key
                valueName      = $pol.valueName
                categoryId     = $categoryId
                supportedOnId  = $supportedOnId
                presentationId = $pol.presentation
                enabledValue   = Get-AdmxPolicyValue $pol.enabledValue
                disabledValue  = Get-AdmxPolicyValue $pol.disabledValue
                elements       = $elements
            })
        }
    }
}

function Get-AdmxCategoryPath {
    # Walks parentId up to the root and returns the display names top-down.
    # The $visited guard breaks the cycle a malformed .admx could introduce.
    param([string]$CategoryId, [hashtable]$CategoriesById)

    $names = New-Object System.Collections.Generic.List[string]
    $visited = @{}
    $currentId = $CategoryId
    while ($currentId -and $CategoriesById.ContainsKey($currentId) -and -not $visited.ContainsKey($currentId)) {
        $visited[$currentId] = $true
        $cat = $CategoriesById[$currentId]
        $names.Insert(0, $cat.displayName)
        $currentId = $cat.parentId
    }
    return $names
}

function New-AdmxIndex {
        [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$PolicyDefinitionsPath,
        [string]$Language,
        [string]$FallbackLanguage,
        [string]$OutputPath,
        [string]$SourceFingerprint
    )
    if ($PSCmdlet.ShouldProcess('New-AdmxIndex', 'Invoke')) {

    if (-not (Test-Path -LiteralPath $PolicyDefinitionsPath)) {
        throw "PolicyDefinitions folder not found: $PolicyDefinitionsPath"
    }

    $state = New-AdmxIndexState
    $admxFiles = @(Get-ChildItem -LiteralPath $PolicyDefinitionsPath -Filter '*.admx' -File)

    # A single unparsable .admx must not abort the whole index: warn and
    # keep going, exactly as before.
    $i = 0
    foreach ($f in $admxFiles) {
        $i++
        Write-Progress -Activity 'Indexing ADMX/ADML' -Status $f.Name -PercentComplete (($i / $admxFiles.Count) * 100)
        try {
            Import-AdmxFile -State $state -AdmxFile $f -PolicyDefinitionsPath $PolicyDefinitionsPath -Language $Language -FallbackLanguage $FallbackLanguage
        }
        catch {
            Write-Warning "Failed to parse $($f.Name): $($_.Exception.Message)"
        }
    }
    Write-Progress -Activity 'Indexing ADMX/ADML' -Completed

    if ($state.SkippedAdmxFiles.Count -gt 0) {
        Write-Warning "$($state.SkippedAdmxFiles.Count) ADMX file(s) excluded from the index for lack of ADML ($Language and $FallbackLanguage not found): $($state.SkippedAdmxFiles -join ', ')"
    }

    # Category paths and "Supported on" text can only be resolved once every
    # file has been read: both routinely cross .admx boundaries.
    $categoriesOut = New-Object System.Collections.Generic.List[object]
    foreach ($catId in $state.CategoriesById.Keys) {
        $cat = $state.CategoriesById[$catId]
        $path = Get-AdmxCategoryPath -CategoryId $catId -CategoriesById $state.CategoriesById
        $categoriesOut.Add([ordered]@{
            id          = $cat.id
            name        = $cat.name
            namespace   = $cat.namespace
            displayName = $cat.displayName
            parentId    = $cat.parentId
            path        = $path
            pathText    = ($path -join ' > ')
        })
    }

    $policiesOut = New-Object System.Collections.Generic.List[object]
    foreach ($pol in $state.Policies) {
        $catPath = @()
        if ($pol.categoryId) { $catPath = Get-AdmxCategoryPath -CategoryId $pol.categoryId -CategoriesById $state.CategoriesById }
        $supportedOnText = $null
        if ($pol.supportedOnId -and $state.SupportedOnById.ContainsKey($pol.supportedOnId)) {
            $supportedOnText = $state.SupportedOnById[$pol.supportedOnId]
        }
        $pol.categoryPath     = $catPath
        $pol.categoryPathText = ($catPath -join ' > ')
        $pol.supportedOnText  = $supportedOnText
        $policiesOut.Add($pol)
    }

    $index = [ordered]@{
        meta = [ordered]@{
            generatedAt           = (Get-Date).ToString('o')
            language              = $Language
            fallbackLanguage      = $FallbackLanguage
            policyDefinitionsPath = $PolicyDefinitionsPath
            admxFileCount         = $admxFiles.Count
            skippedAdmxCount      = $state.SkippedAdmxFiles.Count
            skippedAdmxFiles      = @($state.SkippedAdmxFiles)
            categoryCount         = $categoriesOut.Count
            policyCount           = $policiesOut.Count
            sourceFingerprint     = $SourceFingerprint
        }
        categories = $categoriesOut
        policies   = $policiesOut
    }

    Write-IndexFile -Index $index -Path $OutputPath -Depth 12 -Compress

    Write-Output "Index generated: $OutputPath"
    Write-Output "  ADMX files     : $($admxFiles.Count)"
    Write-Output "  Categories     : $($categoriesOut.Count)"
    Write-Output "  Policies       : $($policiesOut.Count)"

    }
}

# ###########################################################################
# Security settings indexer
# ###########################################################################

function New-SecurityIndex {
    <#
        Merges the static catalog (SecurityCatalog.ps1) with the current
        state read from secedit.inf.

        secedit.inf uses the same INI format as GptTmpl.inf (GptTmplFile.ps1
        parser reused as-is) but is NOT the real GPO file under System32:
        it's a snapshot produced by `secedit /export /cfg` at app startup,
        reflecting the EFFECTIVE system state rather than a hand-managed
        GptTmpl.inf - see plan-gpedit-security-secedit-cycle.md.
    #>
        [CmdletBinding(SupportsShouldProcess)]
    param([string]$SecEditInfPath, [string]$OutputPath)
    if ($PSCmdlet.ShouldProcess('New-SecurityIndex', 'Invoke')) {

    $gpt = Read-GptTmplInf -Path $SecEditInfPath
    $fileExists = Test-Path -LiteralPath $SecEditInfPath

    # Enumerated once and reused below for the out-of-catalog pass: walking
    # the catalog is the expensive part of this build.
    $catalogEntries = @(Get-SecurityCatalogEntry)

    $settings = New-Object System.Collections.Generic.List[object]
    $catalogKeys = @{}

    foreach ($entry in $catalogEntries) {
        $id = "$($entry.section)::$($entry.name)"
        $catalogKeys[$id] = $true

        $raw = Get-GptTmplValue -GptTmpl $gpt -Section $entry.section -Key $entry.name
        $isConfigured = $null -ne $raw

        # LegalNoticeCaption/LegalNoticeText (Security Options) carry
        # alwaysConfigured = $true in the catalog: by explicit user choice
        # these two settings must always show as defined, with "Define this
        # policy setting" checked and locked (see Show-SecurityEditDialog in
        # EditDialogs.ps1 for the UI-side lock).
        if ($entry.alwaysConfigured) { $isConfigured = $true }

        $item = [ordered]@{
            id               = $id
            category         = $entry.category
            section          = $entry.section
            name             = $entry.name
            catalogKey       = $entry.catalogKey
            displayName      = $entry.displayName
            description      = $entry.description
            explain          = $entry.explain
            valueType        = $entry.valueType
            isConfigured     = $isConfigured
            rawValue         = $raw
            members          = $null
            choices          = $null
            flags            = $null
            regType          = $entry.regType
            alwaysConfigured = $entry.alwaysConfigured
        }

        # Type-specific extras: every key above is always present (even as
        # $null) so consumers running under Set-StrictMode -Version Latest
        # never hit a missing property.
        switch ($entry.valueType) {
            'principal-list' { $item.members = if ($isConfigured) { ConvertTo-PrivilegeMemberList -Value $raw } else { , @() } }
            'reg-enum'       { $item.choices = $entry.choices }
            'reg-flags'      { $item.flags   = $entry.flags }
        }

        $settings.Add($item)
    }

    # Keys present in the file but absent from the catalog (out-of-scope or
    # unknown settings) are kept as-is, so nothing is lost when the file is
    # rewritten later.
    $otherSettings = New-Object System.Collections.Generic.List[object]
    foreach ($secName in $gpt.Sections.Keys) {
        foreach ($key in $gpt.Sections[$secName].Keys) {
            if (-not $catalogKeys.ContainsKey("$secName`::$key")) {
                $otherSettings.Add([ordered]@{ section = $secName; name = $key; rawValue = $gpt.Sections[$secName][$key] })
            }
        }
    }

    $index = [ordered]@{
        meta = [ordered]@{
            generatedAt     = (Get-Date).ToString('o')
            secEditInfPath  = $SecEditInfPath
            secEditInfFound = $fileExists
            settingCount    = $settings.Count
        }
        settings      = $settings
        otherSettings = $otherSettings
    }

    Write-IndexFile -Index $index -Path $OutputPath -Depth 10 -Compress

    Write-Output "Security index generated: $OutputPath"
    Write-Output "  secedit.inf found: $fileExists ($SecEditInfPath)"
    Write-Output "  Cataloged settings: $($settings.Count)"
    Write-Output "  Out-of-catalog settings kept: $($otherSettings.Count)"

    }
}

# ###########################################################################
# Advanced Audit Policy indexer
# ###########################################################################

function New-AdvancedAuditIndex {
    # Merges the static catalog (AdvancedAuditCatalog.ps1) with the current
    # state from audit.csv, if present. Same spirit as New-SecurityIndex,
    # matched on the stable Microsoft subcategory GUID.
        [CmdletBinding(SupportsShouldProcess)]
    param([string]$AuditCsvPath, [string]$OutputPath)
    if ($PSCmdlet.ShouldProcess('New-AdvancedAuditIndex', 'Invoke')) {

    $rows = Read-AuditCsv -Path $AuditCsvPath
    $fileExists = Test-Path -LiteralPath $AuditCsvPath

    $settings = New-Object System.Collections.Generic.List[object]
    foreach ($entry in (Get-AdvancedAuditCatalogEntry)) {
        $row = Get-AuditCsvValue -Rows $rows -Guid $entry.guid
        $isConfigured = $null -ne $row

        $settings.Add([ordered]@{
            id           = "AdvAudit::$($entry.guid)"
            category     = $entry.category
            guid         = $entry.guid
            name         = $entry.name
            displayName  = $entry.displayName
            # No documentation text for advanced audit subcategories, but
            # the keys stay present so the shape matches the security index.
            description  = ''
            explain      = ''
            valueType    = $entry.valueType
            isConfigured = $isConfigured
            rawValue     = if ($isConfigured) { $row['Setting Value'] } else { $null }
        })
    }

    $index = [ordered]@{
        meta = [ordered]@{
            generatedAt   = (Get-Date).ToString('o')
            auditCsvPath  = $AuditCsvPath
            auditCsvFound = $fileExists
            settingCount  = $settings.Count
        }
        settings = $settings
    }

    Write-IndexFile -Index $index -Path $OutputPath -Depth 10 -Compress

    Write-Output "Advanced audit index generated: $OutputPath"
    Write-Output "  audit.csv found: $fileExists ($AuditCsvPath)"
    Write-Output "  Subcategories cataloged: $($settings.Count)"

    }
}

# ###########################################################################
# CIS benchmark indexer
# ###########################################################################

function Get-CisField {
    # Extracts a "key : value" field from inside a <custom_item> block.
    #
    # The lookahead for the "next field key" requires at least one
    # indentation space (all real field keys in these files have one, e.g.
    # "      info        :"). Without that guard, a free-text pseudo-label at
    # the start of a line ("Note:", "Caution:", "Impact:" - common inside
    # info/solution, always at column 0) gets mistaken for the end of the
    # current field and silently truncates real text (real bug: "The
    # recommended state for this setting is:" went missing from "info" for
    # ~20 entries).
    param([string]$BlockText, [string]$FieldName)

    $pattern = "(?ms)^\s*$FieldName\s*:\s*(.+?)(?=\r?\n[ \t]+[a-zA-Z_]+\s*:|\z)"
    $m = [regex]::Match($BlockText, $pattern)
    if (-not $m.Success) { return $null }
    return $m.Groups[1].Value.Trim().Trim('"').Trim()
}

function Get-CisSpec {
    # File header <spec> block: which benchmark/version/profile this .audit
    # file covers. Preferred over parsing the file name (more robust).
    param([string]$Text)

    $m = [regex]::Match($Text, '(?s)<spec>.*?<name>(?<name>.*?)</name>.*?<profile>(?<profile>.*?)</profile>.*?<version>(?<version>.*?)</version>.*?</spec>')
    if (-not $m.Success) { return $null }

    $profileParts = $m.Groups['profile'].Value.Trim() -split '\s+'
    return [ordered]@{
        benchmark = $m.Groups['name'].Value.Trim()
        version   = $m.Groups['version'].Value.Trim()
        level     = $profileParts[0]
        role      = if ($profileParts.Count -gt 1) { $profileParts[1] } else { $null }
    }
}

function Get-CisVariable {
    # File header <variables> block: name -> <default>, used to resolve the
    # "@NAME@" placeholders found in value_data.
    param([string]$Text)

    $vars = @{}
    foreach ($vm in [regex]::Matches($Text, '(?s)<variable>(.*?)</variable>')) {
        $body = $vm.Groups[1].Value
        $nameM = [regex]::Match($body, '(?s)<name>(.*?)</name>')
        $defM = [regex]::Match($body, '(?s)<default>(.*?)</default>')
        if ($nameM.Success -and $defM.Success) {
            $vars[$nameM.Groups[1].Value.Trim()] = $defM.Groups[1].Value.Trim()
        }
    }
    return $vars
}

function Resolve-CisValueData {
    # Substitutes "@NAME@" variables, then normalizes each alternative of an
    # "A" || "B" value by stripping the quotes around each segment while
    # keeping the "||" separator: turning that into readable text ("A or B")
    # is the UI's job, so no language gets baked into the index.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Variables', Justification = 'Used inside the nested MatchEvaluator scriptblock, invisible to this analyzer rule.')]
    param([string]$Raw, [hashtable]$Variables)

    if ([string]::IsNullOrEmpty($Raw)) { return $Raw }
    $resolved = [regex]::Replace($Raw, '@([A-Za-z0-9_]+)@', {
        param($m)
        $name = $m.Groups[1].Value
        if ($Variables.ContainsKey($name)) { return $Variables[$name] }
        return $m.Value
    })
    $segments = $resolved -split '\s*\|\|\s*' | ForEach-Object { $_.Trim().Trim('"').Trim() }
    return ($segments -join ' || ')
}

function Get-CisRecommendedStateText {
    <#
        From the "info" field (multi-paragraph text separated by blank
        lines), extracts what follows "The recommended state for this
        setting is:" - the same sentence bolded in the CIS recommendation tab
        (EditDialogs.ps1, Add-CisInfoParagraph) and shown in the "CIS States"
        column of the main grid.

        The ":" isn't always there ("is: Enabled" vs "is Enabled") and the
        sentence isn't always at line start, so the match stops at the first
        sentence end (". " or a trailing ".") rather than at end of line:
        some items ("Configure NetBIOS settings", "Password Settings:
        Password Complexity") chain a second sentence on the same source line
        without a paragraph break. Variant seen in User Rights Assignment:
        "...for this setting on Domain Controllers is: ...".
    #>
    param([string]$Info)

    if ([string]::IsNullOrEmpty($Info)) { return $null }
    $m = [regex]::Match($Info, 'The recommended state for this (?:policy )?setting(?: on [A-Za-z ]+?)? is\s*:?\s*(?<state>.+?)(?:\.(?=\s|$)|\r?\n|$)')
    if (-not $m.Success) { return $null }
    $state = $m.Groups['state'].Value.Trim()

    # Some "X or higher" items chain a fixed equivalence clause right after
    # the recommended value on the same line - in at least one file (2016)
    # with no separating period, which defeats the rule above. Fixed CIS
    # wording, so it is safe to strip even without punctuation.
    $state = $state -replace '\s+Configuring this setting to .+? also conforms to the benchmark\.?\s*$', ''
    return $state.Trim()
}

function ConvertTo-CisNumberAndTitle {
    # Splits "18.10.13.1 Ensure '...' is set to '...'" into its CIS number
    # and title. Returns $null for an unnumbered item, which is never a
    # standalone recommendation (always a sub-condition of an AND/OR block).
    param([string]$Description)

    if ([string]::IsNullOrEmpty($Description)) { return $null }
    $m = [regex]::Match($Description, '^(?<num>\d+(\.\d+)*)\s+(?<title>.+)$')
    if (-not $m.Success) { return $null }

    # Some files (e.g. 2016) prefix the title with "(L1) "/"(L2) ", which is
    # redundant with the level already carried by the profile - stripped so
    # the title stays identical across benchmark versions.
    $title = $m.Groups['title'].Value -replace '^\(L\d\)\s*', ''
    return [ordered]@{ cisNumber = $m.Groups['num'].Value; title = $title.Trim() }
}

function Get-CisAdmxRequirementNote {
    <#
        Extracts, from a <custom_item>'s "solution" field, the ADMX template
        this control depends on - if any. Four phrasings observed across the
        23 bundled .audit files:
          - "is provided by the Group Policy template X.admx/adml that is
            included with the <Windows version> (or newer)." -> bundled with
            Windows, conditional on OS/Administrative Templates version.
          - "may not exist by default. It is provided by the Group Policy
            template X..." -> same meaning, worded as a caveat first.
          - "does not exist by default. An additional Group Policy template
            ( X.admx/adml ) is required - ..." -> never bundled with
            Windows, a manual download from Microsoft (Security Compliance
            Toolkit: SecGuide.admx, MSS-legacy.admx...).
          - "is NOT provided by Microsoft. The Group Policy template X.admx/
            adml is included with the CIS ..." -> third-party (CIS-branded),
            not from Microsoft at all.
        Returns $null if none of the four match - most controls have no ADMX
        dependency note at all (a Windows Service, a firewall setting,
        anything with no Administrative Templates equivalent).

        The note is not always the first one in the "solution" field: when a
        control already carries other notes, the ADMX one is numbered
        ("Note #2:", "Note #3:"). Matching only a bare "Note:" silently lost
        6 controls (18.4.5/18.4.6/18.4.7 SecGuide.admx, 18.10.6.2
        AppXRuntime.admx, 18.6.7.5 LanmanServer.admx, 18.6.8.5
        LanmanWorkstation.admx), which then showed up in "CIS - Catalog
        gaps" as unexplained instead of in "CIS - Missing ADMX templates"
        with the template to install - see plan-gpedit-cis-admx-check.md §3.3.
    #>
    param([string]$Solution)

    if ([string]::IsNullOrEmpty($Solution)) { return $null }

    # "Note:" or "Note #<n>:" - both introduce the same four phrasings.
    $notePrefix = 'Note(?:\s*#\d+)?:\s*'
    # "included with the <version-specific text>" for a template new to a
    # given OS/CIS revision, vs. "included with all versions of the <text>"
    # for a template bundled since XP/2003 (Sharing.admx, AttachmentManager.admx...)
    # - both phrasings appear verbatim across the bundled .audit files, so
    # both must be accepted or the "all versions of" controls fall through
    # to "CIS - Catalog gaps" as unexplained instead of "Missing ADMX templates".
    $includedWith = 'included with (?:all versions of )?the\s+([^\r\n]+)'
    $patterns = @(
        @{ Category = 'BundledConditional'; HasVersion = $true;  Regex = $notePrefix + 'This Group Policy path is provided by the Group Policy template\s+([A-Za-z0-9_.\-]+\.admx)/adml\s+that is ' + $includedWith }
        @{ Category = 'BundledConditional'; HasVersion = $true;  Regex = $notePrefix + 'This Group Policy path may not exist by default\.\s*It is provided by the Group Policy template\s+([A-Za-z0-9_.\-]+\.admx)/adml\s+that is ' + $includedWith }
        @{ Category = 'ManualDownload';     HasVersion = $false; Regex = $notePrefix + 'This Group Policy path does not exist by default\.\s*An additional Group Policy template\s*\(\s*([A-Za-z0-9_.\-]+\.admx)/adml\s*\)\s*is required' }
        @{ Category = 'ThirdParty';         HasVersion = $true;  Regex = $notePrefix + 'This Group Policy path is NOT provided by Microsoft\.\s*The Group Policy template\s+([A-Za-z0-9_.\-]+\.admx)/adml\s+is ' + $includedWith }
    )

    foreach ($p in $patterns) {
        $m = [regex]::Match($Solution, $p.Regex)
        if (-not $m.Success) { continue }
        $versionText = if ($p.HasVersion) { $m.Groups[2].Value.Trim().TrimEnd('.') } else { $null }
        return [ordered]@{ file = $m.Groups[1].Value; category = $p.Category; versionText = $versionText }
    }
    return $null
}

function Test-CisNotGpoConfigurable {
    <#
        18.3.1 "Ensure LAPS AdmPwd GPO Extension / CSE is installed" checks
        HKLM\...\Winlogon\GPExtensions\{D76B9641-...} DllName - the CSE's own
        self-registration entry, written by the LAPS installer, not a value
        any Administrative Template ever exposes. Get-CisAdmxRequirementNote
        correctly returns $null for it (its solution text has no ADMX note -
        there's genuinely no template to install), which otherwise dumps it
        into "CIS - Catalog gaps" alongside real, fixable gaps (missing
        catalog entry / code mapping) even though this one is not fixable at
        all: no ADMX policy will ever back a CSE registration check. Flagged
        here by registry path so both gap reports can exclude it instead of
        mislabeling it as an actionable gap.
    #>
    param([string]$RegKey)

    if ([string]::IsNullOrEmpty($RegKey)) { return $false }
    return $RegKey -match '\\Winlogon\\GPExtensions\\'
}

function Get-CisMatchKey {
    # Maps one .audit control to the (bucket, key) pair the app looks it up
    # by - see plan-gpedit-cis.md §4. $null means "no primary key": the
    # caller then either defers the item to the title-fallback pass or
    # counts it as skipped.
    param(
        [string]$Type,
        [string]$RegKey,
        [string]$RegItem,
        [string]$AccountPolicyName,
        [string]$LockoutPolicy,
        [string]$RightType,
        [string]$AuditSubcategory,
        [string]$CheckType,
        [string]$AccountType
    )

    switch ($Type) {
        # REG_CHECK matches exactly like REGISTRY_SETTING, but names its
        # fields the other way round: "value_data" carries the registry PATH
        # and "key_item" the value NAME. Read-CisAuditFile already swaps them
        # before calling, so both types share this one case. Confirmed
        # against real entries (18.9.19.5/.7 "Turn off background refresh of
        # Group Policy": value_data = "HKLM\...\Policies\System", key_item =
        # "DisableBkGndGroupPolicy").
        { $_ -in 'REGISTRY_SETTING', 'REG_CHECK' } {
            if (-not $RegKey -or -not $RegItem) { return $null }
            # HKLM\ for Computer Configuration entries; HKU\...\S-1-5-21-*
            # (see reg_include_hku_users) for User Configuration entries
            # that can't be checked offline via a fixed HKCU hive - the ADMX
            # index's registryKey (Build-Index.ps1 -Kind Admx, $pol.key) never
            # carries a hive prefix either way, so both must be stripped for
            # byRegistry to match Get-CisRecommendationForRegistry's key.
            $normKey = ($RegKey -replace '^(HKLM|HKU)\\', '').ToLowerInvariant()
            return [ordered]@{ bucket = 'byRegistry'; key = "$normKey|$($RegItem.ToLowerInvariant())" }
        }
        'PASSWORD_POLICY' {
            if (-not $AccountPolicyName) { return $null }
            return [ordered]@{ bucket = 'byPasswordPolicy'; key = $AccountPolicyName }
        }
        'LOCKOUT_POLICY' {
            if (-not $LockoutPolicy) { return $null }
            return [ordered]@{ bucket = 'byLockoutPolicy'; key = $LockoutPolicy }
        }
        'USER_RIGHTS_POLICY' {
            if (-not $RightType) { return $null }
            return [ordered]@{ bucket = 'byUserRight'; key = $RightType }
        }
        'AUDIT_POLICY_SUBCATEGORY' {
            if (-not $AuditSubcategory) { return $null }
            return [ordered]@{ bucket = 'byAuditSubcategory'; key = $AuditSubcategory }
        }
        'CHECK_ACCOUNT' {
            # Two different shapes share this .audit type (see
            # plan-gpedit-new-gpo-cis-generation.md §4.3): a rename check
            # (check_type = CHECK_NOT_REGEX/CHECK_NOT_EQUAL - "must NOT
            # match/equal X", no single correct answer, genuinely
            # organization-specific) vs. a plain status check (no check_type
            # - "must equal Disabled", a normal fixed recommendation). Only
            # the rename shape goes to byOrgValue; the status shape returns
            # $null on purpose so the caller defers it to the title-fallback
            # pass, same path as ANONYMOUS_SID_SETTING.
            if (-not $CheckType) { return $null }
            switch ($AccountType) {
                'ADMINISTRATOR_ACCOUNT' { return [ordered]@{ bucket = 'byOrgValue'; key = 'RenameAdministratorAccount' } }
                'GUEST_ACCOUNT'         { return [ordered]@{ bucket = 'byOrgValue'; key = 'RenameGuestAccount' } }
                default { return $null }
            }
        }
        'BANNER_CHECK' {
            # Always organization-specific (a logon banner has no universal
            # recommended text) despite carrying a real reg_key/reg_item -
            # matched by the stable, Microsoft-defined registry value name
            # rather than folded into byRegistry, so it never gets silently
            # auto-filled with the unresolved "@LEGAL_NOTICE_TEXT@" /
            # "@LEGAL_CAPTION_TEXT@" placeholder.
            switch ($RegItem) {
                'LegalNoticeText'    { return [ordered]@{ bucket = 'byOrgValue'; key = 'LogonMessageText' } }
                'LegalNoticeCaption' { return [ordered]@{ bucket = 'byOrgValue'; key = 'LogonMessageTitle' } }
                default { return $null }
            }
        }
        default { return $null }
    }
}

function Add-CisTitleFallbackCandidate {
    # Records a numbered CIS entry that got no primary match key (REG_CHECK
    # missing value_data/key_item, ANONYMOUS_SID_SETTING - which never
    # carries a location field, or a CHECK_ACCOUNT status check) so it can be
    # resolved after all files are read, via cis-fallback-map.json.
    param(
        [System.Collections.Generic.List[object]]$Candidates,
        [string]$Title,
        [string]$Info,
        [string]$ValueType,
        $Spec,
        [string]$CisNumber
    )

    # Keyed by the extracted setting name (Get-CisSettingNameFromTitle), not
    # the whole CIS sentence: at runtime the app only has a bare
    # SecurityCatalog/ADMX DisplayName to look up with (see
    # Get-CisRecommendationForSecuritySetting's byTitle fallback), never the
    # full "Ensure '...' is set to '...'" phrasing.
    $normalizedTitle = ConvertTo-CisNormalizedTitle -Title (Get-CisSettingNameFromTitle -Title $Title)
    if (-not $normalizedTitle) { return }

    # [pscustomobject], not a plain hashtable: the Group-Object -Property
    # below only resolves real object properties, not hashtable keys - a
    # hashtable would silently group everything under one empty-name bucket.
    $Candidates.Add([pscustomobject]@{
        NormalizedTitle = $normalizedTitle
        Title           = $Title
        Info            = $Info
        ValueType       = $ValueType
        Spec            = $Spec
        CisNumber       = $CisNumber
    })
}

function Read-CisAuditFile {
    # Parses one .audit file and folds every numbered <custom_item> into
    # $Index (or into $TitleFallbackCandidates when it has no usable
    # location field).
    param(
        [string]$Path,
        [System.Collections.IDictionary]$Index,
        [hashtable]$Counters,
        [System.Collections.Generic.List[object]]$TitleFallbackCandidates
    )

    $text = Get-Content -Raw -LiteralPath $Path
    $spec = Get-CisSpec -Text $text
    if ($null -eq $spec) {
        Write-Warning "<spec> block not found, file skipped: $Path"
        return
    }
    $variables = Get-CisVariable -Text $text

    foreach ($blockMatch in [regex]::Matches($text, '(?s)<custom_item>(.*?)</custom_item>')) {
        $body = $blockMatch.Groups[1].Value
        $type = Get-CisField -BlockText $body -FieldName 'type'
        $numberAndTitle = ConvertTo-CisNumberAndTitle -Description (Get-CisField -BlockText $body -FieldName 'description')
        # Unnumbered items are never a standalone recommendation.
        if ($null -eq $numberAndTitle) { continue }

        # REG_CHECK swaps the two location fields compared to
        # REGISTRY_SETTING (see Get-CisMatchKey) - read the right pair here
        # so everything downstream can treat both types identically.
        $isRegCheck = $type -eq 'REG_CHECK'
        $regKey  = Get-CisField -BlockText $body -FieldName $(if ($isRegCheck) { 'value_data' } else { 'reg_key' })
        $regItem = Get-CisField -BlockText $body -FieldName $(if ($isRegCheck) { 'key_item' } else { 'reg_item' })

        $passwordPolicy   = Get-CisField -BlockText $body -FieldName 'password_policy'
        $lockoutPolicy    = Get-CisField -BlockText $body -FieldName 'lockout_policy'
        $rightType        = Get-CisField -BlockText $body -FieldName 'right_type'
        $auditSubcategory = Get-CisField -BlockText $body -FieldName 'audit_policy_subcategory'
        # Only meaningful for CHECK_ACCOUNT - $null elsewhere, harmless.
        $checkType   = Get-CisField -BlockText $body -FieldName 'check_type'
        $accountType = Get-CisField -BlockText $body -FieldName 'account_type'

        $matchKey = Get-CisMatchKey -Type $type -RegKey $regKey -RegItem $regItem `
            -AccountPolicyName $passwordPolicy -LockoutPolicy $lockoutPolicy -RightType $rightType `
            -AuditSubcategory $auditSubcategory -CheckType $checkType -AccountType $accountType

        $info = Get-CisField -BlockText $body -FieldName 'info'
        $valueType = Get-CisField -BlockText $body -FieldName 'value_type'

        if ($null -eq $matchKey) {
            if ($isRegCheck -or $type -eq 'ANONYMOUS_SID_SETTING' -or ($type -eq 'CHECK_ACCOUNT' -and -not $checkType)) {
                # Deferred, not counted as skipped yet - the title-fallback
                # pass may still resolve it into the byTitle bucket; only
                # what is still unresolved after that pass counts as skipped.
                Add-CisTitleFallbackCandidate -Candidates $TitleFallbackCandidates -Title $numberAndTitle.title `
                    -Info $info -ValueType $valueType -Spec $spec -CisNumber $numberAndTitle.cisNumber
                continue
            }
            $Counters.Skipped++
            continue
        }

        $recommendedStateText = Get-CisRecommendedStateText -Info $info

        $bucket = $Index[$matchKey.bucket]
        if (-not $bucket.Contains($matchKey.key)) {
            # title/info/requiredAdmx are fixed at entry creation, from the
            # first .audit file that defines the control - not re-evaluated
            # against a later profile's file for the same key.
            # requiredAdmx only makes sense for byRegistry (the only bucket
            # an Administrative Templates policy can ever back).
            $bucket[$matchKey.key] = [ordered]@{
                bucket               = $matchKey.bucket
                key                  = $matchKey.key
                title                = $numberAndTitle.title
                info                 = $info
                recommendedStateText = $recommendedStateText
                valueType            = $valueType
                regKey               = $regKey
                regItem              = $regItem
                requiredAdmx         = if ($matchKey.bucket -eq 'byRegistry') { Get-CisAdmxRequirementNote -Solution (Get-CisField -BlockText $body -FieldName 'solution') } else { $null }
                notGpoConfigurable   = Test-CisNotGpoConfigurable -RegKey $regKey
                profiles             = New-Object System.Collections.Generic.List[object]
            }
            $Counters.Entries++
        }

        # For REG_CHECK, "value_data" was already consumed above as the
        # registry PATH, so there is no per-profile recommended value to read
        # from the file. Leaving it $null would silently break the CIS Yes/No
        # column, the CIS R. Value column and profile filtering (all treat an
        # empty valueData as "no recommendation for this profile") - use this
        # profile's own recommendedStateText ("Disabled"/"Enabled") instead.
        $valueData = if ($isRegCheck) { $recommendedStateText } else {
            Resolve-CisValueData -Raw (Get-CisField -BlockText $body -FieldName 'value_data') -Variables $variables
        }

        $bucket[$matchKey.key].profiles.Add([ordered]@{
            benchmark = $spec.benchmark
            version   = $spec.version
            level     = $spec.level
            role      = $spec.role
            cisNumber = $numberAndTitle.cisNumber
            valueData = $valueData
        })
        $Counters.Profiles++
    }
}

function Get-CisFallbackMatchSource {
    <#
        Flat list of every setting a CIS title could be auto-paired with:
        Data_SecurityCatalog.json (SecurityOptionsRegistryCatalog - the only
        section with a real RegistryPath/ValueName) then the ADMX index.
        Built once per run and reused for every unresolved title: the ADMX
        index is several MB, and the previous code re-read and re-parsed both
        files for each candidate.
    #>
    param([string]$SecurityCatalogPath, [string]$AdmxIndexPath)

    $sources = New-Object System.Collections.Generic.List[object]

    if (Test-Path -LiteralPath $SecurityCatalogPath) {
        try {
            $catalog = Get-Content -Raw -Encoding UTF8 -LiteralPath $SecurityCatalogPath | ConvertFrom-Json
            foreach ($entry in @($catalog.SecurityOptionsRegistryCatalog)) {
                if (-not $entry.DisplayName -or -not $entry.RegistryPath -or -not $entry.ValueName) { continue }
                $sources.Add([ordered]@{ source = 'securitycatalog'; needle = $entry.DisplayName.ToLowerInvariant(); regKey = $entry.RegistryPath; regItem = $entry.ValueName })
            }
        }
        catch { Write-Warning "Security catalog unreadable during CIS fallback resolution ($SecurityCatalogPath): $($_.Exception.Message)" }
    }

    if (Test-Path -LiteralPath $AdmxIndexPath) {
        try {
            $admx = Get-Content -Raw -Encoding UTF8 -LiteralPath $AdmxIndexPath | ConvertFrom-Json
            foreach ($pol in @($admx.policies)) {
                if (-not $pol.displayName -or -not $pol.registryKey -or -not $pol.valueName) { continue }
                $sources.Add([ordered]@{ source = 'admx'; needle = $pol.displayName.ToLowerInvariant(); regKey = $pol.registryKey; regItem = $pol.valueName })
            }
        }
        catch { Write-Warning "ADMX index unreadable during CIS fallback resolution ($AdmxIndexPath): $($_.Exception.Message)" }
    }

    return $sources
}

function Resolve-CisTitleAutomatically {
    # Best-effort pairing by simple substring containment: CIS titles
    # literally wrap the catalog's DisplayName in quotes ("Ensure
    # '<DisplayName>' is set to ..."). Only an UNAMBIGUOUS single match is
    # accepted; 0 or 2+ candidates leave the entry unresolved
    # (needsManualReview) rather than risk pairing the wrong setting.
    param([string]$NormalizedTitle, [System.Collections.Generic.List[object]]$MatchSources, [string]$ValueType)

    $candidates = @($MatchSources | Where-Object { $NormalizedTitle.Contains($_.needle) })
    if ($candidates.Count -ne 1) { return $null }

    $c = $candidates[0]
    return [ordered]@{ source = $c.source; regKey = $c.regKey; regItem = $c.regItem; valueType = $ValueType; valueMap = $null; needsManualReview = $false }
}

function Resolve-CisTitleFallbackCandidate {
    <#
        Second-chance matching for the candidates collected by
        Read-CisAuditFile: resolves each distinct title through
        cis-fallback-map.json, auto-filling that map where an unambiguous
        match exists and flagging the rest needsManualReview. Populates the
        byTitle bucket and returns $true if the map gained new keys (the
        caller then writes it back).
    #>
    param(
        [System.Collections.Generic.List[object]]$Candidates,
        [System.Collections.IDictionary]$Index,
        [hashtable]$Counters,
        [hashtable]$FallbackMap,
        [string]$SecurityCatalogPath,
        [string]$AdmxIndexPath
    )

    $fallbackMapDirty = $false
    # Loaded lazily: a complete fallback map (the normal case) means no
    # auto-resolution is needed and neither source file is ever read.
    $matchSources = $null

    foreach ($group in ($Candidates | Group-Object -Property NormalizedTitle)) {
        $normTitle = $group.Name
        $first = $group.Group[0]

        $fbEntry = $null
        if ($FallbackMap.ContainsKey($normTitle)) {
            if (-not $FallbackMap[$normTitle].needsManualReview) { $fbEntry = $FallbackMap[$normTitle] }
        }
        else {
            if ($null -eq $matchSources) {
                $matchSources = Get-CisFallbackMatchSource -SecurityCatalogPath $SecurityCatalogPath -AdmxIndexPath $AdmxIndexPath
            }
            $resolved = Resolve-CisTitleAutomatically -NormalizedTitle $normTitle -MatchSources $matchSources -ValueType $first.ValueType
            if ($resolved) {
                $FallbackMap[$normTitle] = $resolved
                $fbEntry = $resolved
            }
            else {
                $FallbackMap[$normTitle] = [ordered]@{ source = 'manual'; regKey = $null; regItem = $null; valueType = $first.ValueType; valueMap = $null; needsManualReview = $true }
            }
            $fallbackMapDirty = $true
        }

        if ($null -eq $fbEntry) {
            $Counters.NeedsManualReview++
            $Counters.Skipped += $group.Group.Count
            continue
        }

        $Index.byTitle[$normTitle] = [ordered]@{
            bucket               = 'byTitle'
            key                  = $normTitle
            title                = $first.Title
            info                 = $first.Info
            recommendedStateText = Get-CisRecommendedStateText -Info $first.Info
            valueType            = $fbEntry.valueType
            regKey               = $fbEntry.regKey
            regItem              = $fbEntry.regItem
            # byTitle entries never carry a "solution" field (they come from
            # cis-fallback-map.json, not from one .audit block) - present
            # with $null rather than omitted, so every bucket's entries share
            # the same shape under the app's Set-StrictMode -Version Latest,
            # where a missing property throws but a $null one does not.
            requiredAdmx         = $null
            notGpoConfigurable   = Test-CisNotGpoConfigurable -RegKey $fbEntry.regKey
            profiles             = New-Object System.Collections.Generic.List[object]
        }
        $Counters.Entries++

        foreach ($cand in $group.Group) {
            # These entries have no value_data at all: the recommended value
            # only exists if the fallback map declares a state -> value map.
            $stateText = Get-CisRecommendedStateText -Info $cand.Info
            $valueData = $null
            if ($fbEntry.valueMap -and $stateText -and $fbEntry.valueMap.PSObject.Properties[$stateText]) {
                $valueData = $fbEntry.valueMap.$stateText
            }
            $Index.byTitle[$normTitle].profiles.Add([ordered]@{
                benchmark = $cand.Spec.benchmark
                version   = $cand.Spec.version
                level     = $cand.Spec.level
                role      = $cand.Spec.role
                cisNumber = $cand.CisNumber
                valueData = $valueData
            })
            $Counters.Profiles++
        }
    }

    return $fallbackMapDirty
}

function New-CisIndex {
    <#
        Parses every CIS .audit file (Tenable Nessus format) in
        $AuditFilesPath and produces one index grouping, per covered setting,
        the shared description/info plus the list of recommendations per
        profile (benchmark, version, L1/L2 level, MS/DC role).
    #>
        [CmdletBinding(SupportsShouldProcess)]
    param([string]$AuditFilesPath, [string]$OutputPath, [string]$SourceFingerprint)
    if ($PSCmdlet.ShouldProcess('New-CisIndex', 'Invoke')) {

    if (-not (Test-Path -LiteralPath $AuditFilesPath)) {
        throw "Audit files folder not found: $AuditFilesPath"
    }
    $files = @(Get-ChildItem -LiteralPath $AuditFilesPath -Filter '*.audit' | Sort-Object Name)
    if ($files.Count -eq 0) {
        throw "No *.audit file found in $AuditFilesPath"
    }

    $index = [ordered]@{
        byRegistry         = [ordered]@{}
        byPasswordPolicy   = [ordered]@{}
        byLockoutPolicy    = [ordered]@{}
        byUserRight        = [ordered]@{}
        byAuditSubcategory = [ordered]@{}
        byTitle            = [ordered]@{}
        # Organization-specific items (account rename / logon banner text)
        # with NO universal recommended value - see Get-CisMatchKey's
        # CHECK_ACCOUNT/BANNER_CHECK cases and CisCatalog.ps1's
        # Get-CisOrgValueEntry. Deliberately NOT in $script:CisIndexBuckets
        # (CisCatalog.ps1): these must stay out of Get-CisAllEntry and of
        # the CIS Yes/No column and profile filter, which all assume a fixed
        # recommended value exists.
        byOrgValue         = [ordered]@{}
    }
    $counters = @{ Entries = 0; Profiles = 0; Skipped = 0; NeedsManualReview = 0 }
    $titleFallbackCandidates = New-Object System.Collections.Generic.List[object]

    foreach ($f in $files) {
        Read-CisAuditFile -Path $f.FullName -Index $index -Counters $counters -TitleFallbackCandidates $titleFallbackCandidates
    }

    # cis-fallback-map.json and cis-overrides.json live next to the index
    # being written, not next to this script.
    $dataPath = Split-Path -Parent $OutputPath

    # Title-fallback pass: only newly-added keys are written back, existing
    # entries (especially manual ones) are never touched.
    if ($titleFallbackCandidates.Count -gt 0) {
        $fallbackMap = Get-CisFallbackMap -DataPath $dataPath
        $fallbackMapDirty = Resolve-CisTitleFallbackCandidate -Candidates $titleFallbackCandidates -Index $index -Counters $counters `
            -FallbackMap $fallbackMap `
            -SecurityCatalogPath (Join-Path $PSScriptRoot '..\DefaultData\Data_SecurityCatalog.json') `
            -AdmxIndexPath (Join-Path $dataPath 'admx-index.json')

        if ($fallbackMapDirty) {
            $orderedFallbackMap = [ordered]@{}
            foreach ($k in ($fallbackMap.Keys | Sort-Object)) { $orderedFallbackMap[$k] = $fallbackMap[$k] }
            $fallbackMapOutPath = Get-CisFallbackMapPath -DataPath $dataPath
            $fallbackMapOutDir = Split-Path -Parent $fallbackMapOutPath
            if (-not (Test-Path -LiteralPath $fallbackMapOutDir)) { New-Item -ItemType Directory -Path $fallbackMapOutDir -Force | Out-Null }
            # Explicit UTF8Encoding($true): this file is read back with
            # -Encoding UTF8 and must keep its BOM.
            [System.IO.File]::WriteAllText($fallbackMapOutPath, ($orderedFallbackMap | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($true)))
        }
    }

    # "info" overrides (see plan-gpedit-security-catalog-editor.md §4.3):
    # applied here too, in addition to Import-CisIndex app-side, so UI edits
    # survive a full regeneration. Still plain hashtables at this point (not
    # yet PSCustomObjects from ConvertFrom-Json), hence direct key indexing
    # rather than the .PSObject.Properties walk Merge-CisOverride does.
    $overrides = Get-CisOverride -DataPath $dataPath
    foreach ($overrideKey in $overrides.Keys) {
        $parts = $overrideKey -split '::', 2
        if ($parts.Count -ne 2) { continue }
        $bucket = $index[$parts[0]]
        if ($bucket -and $bucket.Contains($parts[1])) {
            $bucket[$parts[1]].info = $overrides[$overrideKey].info
        }
    }

    # meta first, then every bucket in declaration order - copied from
    # $index rather than re-listed, so adding a bucket above is enough.
    $output = [ordered]@{
        meta = [ordered]@{
            generatedAt            = (Get-Date).ToString('o')
            sourceFiles            = @($files | ForEach-Object { $_.Name })
            entryCount             = $counters.Entries
            profileCount           = $counters.Profiles
            skippedItemCount       = $counters.Skipped
            needsManualReviewCount = $counters.NeedsManualReview
            sourceFingerprint      = $SourceFingerprint
        }
    }
    foreach ($bucketName in $index.Keys) { $output[$bucketName] = $index[$bucketName] }

    Write-IndexFile -Index $output -Path $OutputPath -Depth 10

    Write-Output "CIS index generated: $OutputPath"
    Write-Output "  .audit files processed: $($files.Count)"
    Write-Output "  Entries (unique controls): $($counters.Entries)"
    Write-Output "  Recommendations per profile: $($counters.Profiles)"
    Write-Output "  Items skipped (out-of-scope type or missing fields): $($counters.Skipped)"
    Write-Output "  Fallback-map entries needing manual review: $($counters.NeedsManualReview)"

    }
}

# ###########################################################################
# Dispatch
# ###########################################################################

if (-not $OutputPath) {
    $defaultOutputName = @{
        Admx          = 'admx-index.json'
        Security      = 'security-index.json'
        AdvancedAudit = 'advanced-audit-index.json'
        Cis           = 'cis-index.json'
    }
    $OutputPath = Join-Path (Join-Path $PSScriptRoot '..\..\data') $defaultOutputName[$Kind]
}

# Dependencies are dot-sourced per kind, at script scope so every function
# above can see them, and only for the kind actually being built (loading the
# security catalog for an ADMX build would be pure overhead).
switch ($Kind) {
    'Security' {
        . (Join-Path $PSScriptRoot '..\Parsers\GptTmplFile.ps1')
        . (Join-Path $PSScriptRoot '..\Catalogs\SecurityCatalog.ps1')
    }
    'AdvancedAudit' {
        . (Join-Path $PSScriptRoot '..\Parsers\AuditCsvFile.ps1')
        . (Join-Path $PSScriptRoot '..\Catalogs\AdvancedAuditCatalog.ps1')
    }
    'Cis' {
        # For Get-CisFallbackMap/Get-CisFallbackMapPath/Get-CisOverride and
        # the title normalization helpers.
        . (Join-Path $PSScriptRoot '..\Catalogs\CisCatalog.ps1')
    }
}

# Strict mode is set AFTER the dot-sources above, which each set their own
# and would otherwise override this one. Per kind, matching what each of the
# four former scripts effectively ran under:
#   - Admx/Cis: off, because both walk dynamic XML/JSON where a missing
#     property must return $null instead of throwing.
#   - Security/AdvancedAudit: strict, as inherited from their catalogs.
if ($Kind -eq 'Admx' -or $Kind -eq 'Cis') { Set-StrictMode -Off } else { Set-StrictMode -Version Latest }

if ($Kind -eq 'Admx') {
    New-AdmxIndex -PolicyDefinitionsPath $PolicyDefinitionsPath -Language $Language `
        -FallbackLanguage $FallbackLanguage -OutputPath $OutputPath -SourceFingerprint $SourceFingerprint
}
elseif ($Kind -eq 'Security') {
    New-SecurityIndex -SecEditInfPath $SecEditInfPath -OutputPath $OutputPath
}
elseif ($Kind -eq 'AdvancedAudit') {
    New-AdvancedAuditIndex -AuditCsvPath $AuditCsvPath -OutputPath $OutputPath
}
else {
    New-CisIndex -AuditFilesPath $AuditFilesPath -OutputPath $OutputPath -SourceFingerprint $SourceFingerprint
}
