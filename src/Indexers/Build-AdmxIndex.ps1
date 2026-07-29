<#
    Step 1 - Indexes Administrative Templates (ADMX/ADML): parses all .admx
    files from C:\Windows\PolicyDefinitions plus their .adml translations
    (en-US only - the app has no language selector), exporting a JSON
    structure (categories + policies) for the rest of gpedit (search, tree, edit).
#>
param(
    [string]$PolicyDefinitionsPath = (Join-Path $env:WinDir 'PolicyDefinitions'),
    [string]$Language = 'en-US',
    [string]$FallbackLanguage = 'en-US',
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\..\data\admx-index.json'),
    # Fingerprint of PolicyDefinitions folder (see PolicyDefinitionsFingerprint.ps1),
    # stored in meta.sourceFingerprint so GpEdit.ps1 can detect a stale cache
    # without re-scanning files here.
    [string]$SourceFingerprint = ''
)

# Strict mode explicitly off: relies on default PowerShell behavior for
# dynamic XML (a missing property on a node - e.g. $pol.supportedOn,
# $pol.elements, $el.key - returns $null instead of throwing). Otherwise the
# caller's (GpEdit.ps1) strict mode would propagate here via "&".
Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Global indexing state
# ---------------------------------------------------------------------------
$script:CategoriesById = @{}     # id -> ordered hashtable
$script:SupportedOnById = @{}    # id -> ordered hashtable (already resolved to text)
$script:Policies = New-Object System.Collections.Generic.List[object]
$script:AdmxFileCount = 0
# .admx files excluded from the index for lack of ADML (requested language
# AND fallback) - see plan-gpedit-ui-enhancements.md §1.
$script:SkippedAdmxFiles = New-Object System.Collections.Generic.List[string]

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

function Get-AdmlStringMap {
    param([xml]$AdmlXml)

    $map = @{}
    if ($null -eq $AdmlXml) { return $map }
    $stringTable = $AdmlXml.policyDefinitionResources.resources.stringTable
    if ($null -eq $stringTable) { return $map }
    foreach ($s in @($stringTable.string)) {
        if ($null -ne $s -and $s.id) {
            $map[$s.id] = $s.'#text'
        }
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
        # Dynamic .label shortcut (PowerShell, lookup by LocalName - reliable
        # even with a default XML namespace on the root, unlike
        # SelectSingleNode('label') without an XmlNamespaceManager) can return
        # either a string or the <label> XmlElement itself depending on node
        # shape, so normalize explicitly instead of blindly calling .Trim()
        # (direct call used to fail parsing on appv.adml).
        $raw = if ($control.LocalName -eq 'textBox') { $control.label } else { $control.InnerText }
        $label = if ($raw -is [System.Xml.XmlElement]) { $raw.InnerText } elseif ($raw -is [string]) { $raw } else { $null }
        if ($label) { $map[$control.refId] = $label.Trim() }
    }
    return $map
}

function Expand-AdmlText {
    param(
        [string]$Value,
        [hashtable]$StringMap
    )
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    $evaluator = {
        param($m)
        $kind = $m.Groups[1].Value
        $key = $m.Groups[2].Value
        if ($kind -eq 'string' -and $StringMap.ContainsKey($key)) {
            return $StringMap[$key]
        }
        return $m.Value
    }
    return [regex]::Replace($Value, '\$\((string|presentation)\.([A-Za-z0-9_\.]+)\)', [System.Text.RegularExpressions.MatchEvaluator]$evaluator)
}

function Get-PolicyValue {
    # Extracts a value (decimal or string) from a node like
    # <enabledValue><decimal value="1"/></enabledValue> or
    # <item><value><string>...</string></value></item>
    param($Node)

    if ($null -eq $Node) { return $null }
    if ($Node.decimal) {
        $raw = $Node.decimal.value
        $parsed = 0
        if ([int]::TryParse($raw, [ref]$parsed)) { return $parsed }
        return $raw
    }
    if ($Node.string -is [string]) { return $Node.string }
    if ($Node.value) { return Get-PolicyValue $Node.value }
    return $null
}

function New-PrefixMap {
    param($PolicyNamespaces, [string]$OwnPrefix, [string]$OwnNamespace)

    $map = @{}
    if ($OwnPrefix) { $map[$OwnPrefix] = $OwnNamespace }
    if ($null -ne $PolicyNamespaces -and $PolicyNamespaces.using) {
        foreach ($u in @($PolicyNamespaces.using)) {
            if ($u.prefix -and $u.namespace) { $map[$u.prefix] = $u.namespace }
        }
    }
    return $map
}

function Resolve-Ref {
    # Converts a "prefix:name" or "name" reference into a unique global id "namespace::name"
    param(
        [string]$Ref,
        [hashtable]$PrefixMap,
        [string]$CurrentNamespace
    )
    if ([string]::IsNullOrEmpty($Ref)) { return $null }
    if ($Ref -match '^(?<p>[^:]+):(?<n>.+)$') {
        $p = $Matches['p']
        $n = $Matches['n']
        if ($PrefixMap.ContainsKey($p)) {
            return "$($PrefixMap[$p])::$n"
        }
        return "$($p)::$n"
    }
    return "$CurrentNamespace::$Ref"
}

function Convert-Element {
    param($ElementNode, [hashtable]$StringMap, [hashtable]$PresentationLabels = @{})

    $item = [ordered]@{
        type      = $ElementNode.LocalName
        id        = $ElementNode.id
        key       = $ElementNode.key
        valueName = $ElementNode.valueName
        required  = ($ElementNode.required -eq 'true')
        # Localized label from the ADML presentation (see
        # Get-AdmlPresentationLabelMap); $null if absent (UI falls back to
        # raw id - EditDialogs.ps1).
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
            if ($ElementNode.trueValue)  { $item.trueValue  = Get-PolicyValue $ElementNode.trueValue }
            if ($ElementNode.falseValue) { $item.falseValue = Get-PolicyValue $ElementNode.falseValue }
        }
        'enum' {
            $enumItems = New-Object System.Collections.Generic.List[object]
            foreach ($it in @($ElementNode.item)) {
                if ($null -eq $it) { continue }
                $enumItems.Add([ordered]@{
                    displayName = Expand-AdmlText -Value $it.displayName -StringMap $StringMap
                    value       = Get-PolicyValue $it.value
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
    param(
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

    $prefixMap = New-PrefixMap -PolicyNamespaces $pd.policyNamespaces -OwnPrefix $targetPrefix -OwnNamespace $targetNs

    # --- Load matching ADML (requested language, then fallback) ---
    $admlPath = Join-Path (Join-Path $PolicyDefinitionsPath $Language) ($AdmxFile.BaseName + '.adml')
    if (-not (Test-Path -LiteralPath $admlPath)) {
        $admlPath = Join-Path (Join-Path $PolicyDefinitionsPath $FallbackLanguage) ($AdmxFile.BaseName + '.adml')
    }
    if (-not (Test-Path -LiteralPath $admlPath)) {
        # No ADML for either requested or fallback language: exclude this
        # ADMX entirely rather than index unresolved raw labels (potentially
        # unreadable "$(string.xxx)" keys) - see plan-gpedit-ui-enhancements.md §1.
        $script:SkippedAdmxFiles.Add($AdmxFile.Name)
        return
    }
    [xml]$adml = Get-Content -LiteralPath $admlPath -Raw -Encoding UTF8
    $stringMap = Get-AdmlStringMap -AdmlXml $adml

    # --- supportedOn definitions (resolved to text locally) ---
    if ($pd.supportedOn -and $pd.supportedOn.definitions -and $pd.supportedOn.definitions.definition) {
        foreach ($def in @($pd.supportedOn.definitions.definition)) {
            $id = "$targetNs::$($def.name)"
            $script:SupportedOnById[$id] = Expand-AdmlText -Value $def.displayName -StringMap $stringMap
        }
    }

    # --- categories ---
    if ($pd.categories -and $pd.categories.category) {
        foreach ($cat in @($pd.categories.category)) {
            $id = "$targetNs::$($cat.name)"
            $parentId = $null
            if ($cat.parentCategory -and $cat.parentCategory.ref) {
                $parentId = Resolve-Ref -Ref $cat.parentCategory.ref -PrefixMap $prefixMap -CurrentNamespace $targetNs
            }
            $script:CategoriesById[$id] = [ordered]@{
                id          = $id
                name        = $cat.name
                namespace   = $targetNs
                displayName = Expand-AdmlText -Value $cat.displayName -StringMap $stringMap
                parentId    = $parentId
            }
        }
    }

    # --- policies ---
    if ($pd.policies -and $pd.policies.policy) {
        foreach ($pol in @($pd.policies.policy)) {
            $categoryId = $null
            if ($pol.parentCategory -and $pol.parentCategory.ref) {
                $categoryId = Resolve-Ref -Ref $pol.parentCategory.ref -PrefixMap $prefixMap -CurrentNamespace $targetNs
            }
            $supportedOnId = $null
            if ($pol.supportedOn -and $pol.supportedOn.ref) {
                $supportedOnId = Resolve-Ref -Ref $pol.supportedOn.ref -PrefixMap $prefixMap -CurrentNamespace $targetNs
            }

            $elements = New-Object System.Collections.Generic.List[object]
            if ($pol.elements) {
                $presentationLabels = Get-AdmlPresentationLabelMap -PresentationRef $pol.presentation -AdmlXml $adml
                foreach ($el in $pol.elements.ChildNodes) {
                    if ($el.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
                    $elements.Add((Convert-Element -ElementNode $el -StringMap $stringMap -PresentationLabels $presentationLabels))
                }
            }

            $script:Policies.Add([ordered]@{
                id                = "$targetNs::$($pol.name)"
                name              = $pol.name
                namespace         = $targetNs
                admxFile          = $AdmxFile.Name
                class             = $pol.class
                displayName       = Expand-AdmlText -Value $pol.displayName -StringMap $stringMap
                explainText       = Expand-AdmlText -Value $pol.explainText -StringMap $stringMap
                registryKey       = $pol.key
                valueName         = $pol.valueName
                categoryId        = $categoryId
                supportedOnId     = $supportedOnId
                presentationId    = $pol.presentation
                enabledValue      = Get-PolicyValue $pol.enabledValue
                disabledValue     = Get-PolicyValue $pol.disabledValue
                elements          = $elements
            })
        }
    }
}

function Get-CategoryPath {
    param([string]$CategoryId)

    $names = New-Object System.Collections.Generic.List[string]
    $visited = @{}
    $currentId = $CategoryId
    while ($currentId -and $script:CategoriesById.ContainsKey($currentId) -and -not $visited.ContainsKey($currentId)) {
        $visited[$currentId] = $true
        $cat = $script:CategoriesById[$currentId]
        $names.Insert(0, $cat.displayName)
        $currentId = $cat.parentId
    }
    return $names
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if (-not (Test-Path -LiteralPath $PolicyDefinitionsPath)) {
    throw "PolicyDefinitions folder not found: $PolicyDefinitionsPath"
}

$admxFiles = Get-ChildItem -LiteralPath $PolicyDefinitionsPath -Filter '*.admx' -File
$script:AdmxFileCount = $admxFiles.Count
$i = 0
foreach ($f in $admxFiles) {
    $i++
    Write-Progress -Activity 'Indexing ADMX/ADML' -Status $f.Name -PercentComplete (($i / $admxFiles.Count) * 100)
    try {
        Import-AdmxFile -AdmxFile $f -PolicyDefinitionsPath $PolicyDefinitionsPath -Language $Language -FallbackLanguage $FallbackLanguage
    }
    catch {
        Write-Warning "Failed to parse $($f.Name): $($_.Exception.Message)"
    }
}
Write-Progress -Activity 'Indexing ADMX/ADML' -Completed

if ($script:SkippedAdmxFiles.Count -gt 0) {
    Write-Warning "$($script:SkippedAdmxFiles.Count) ADMX file(s) excluded from the index for lack of ADML ($Language and $FallbackLanguage not found): $($script:SkippedAdmxFiles -join ', ')"
}

# --- Resolve category paths + "Supported on" text ---
$categoriesOut = New-Object System.Collections.Generic.List[object]
foreach ($catId in $script:CategoriesById.Keys) {
    $cat = $script:CategoriesById[$catId]
    $path = Get-CategoryPath -CategoryId $catId
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
foreach ($pol in $script:Policies) {
    $catPath = @()
    if ($pol.categoryId) { $catPath = Get-CategoryPath -CategoryId $pol.categoryId }
    $supportedOnText = $null
    if ($pol.supportedOnId -and $script:SupportedOnById.ContainsKey($pol.supportedOnId)) {
        $supportedOnText = $script:SupportedOnById[$pol.supportedOnId]
    }
    $pol.categoryPath        = $catPath
    $pol.categoryPathText    = ($catPath -join ' > ')
    $pol.supportedOnText     = $supportedOnText
    $policiesOut.Add($pol)
}

$index = [ordered]@{
    meta = [ordered]@{
        generatedAt           = (Get-Date).ToString('o')
        language               = $Language
        fallbackLanguage       = $FallbackLanguage
        policyDefinitionsPath  = $PolicyDefinitionsPath
        admxFileCount          = $script:AdmxFileCount
        skippedAdmxCount       = $script:SkippedAdmxFiles.Count
        skippedAdmxFiles       = @($script:SkippedAdmxFiles)
        categoryCount          = $categoriesOut.Count
        policyCount            = $policiesOut.Count
        sourceFingerprint      = $SourceFingerprint
    }
    categories = $categoriesOut
    policies   = $policiesOut
}

$outDir = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$index | ConvertTo-Json -Depth 12 -Compress | Out-File -LiteralPath $OutputPath -Encoding utf8

Write-Host "Index generated: $OutputPath"
Write-Host "  ADMX files     : $($script:AdmxFileCount)"
Write-Host "  Categories     : $($categoriesOut.Count)"
Write-Host "  Policies       : $($policiesOut.Count)"
