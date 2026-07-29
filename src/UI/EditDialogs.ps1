<#
    Step 5 - Setting edit windows: one for ADMX policies (dynamic controls
    per element type), one for security settings (numeric value,
    enabled/disabled, account/rights lists...).

    Each Show-*Dialog function shows a modal window and returns either
    $null (cancelled) or a hashtable describing the requested change. The
    actual disk write (registry.pol / GptTmpl.inf) is Step 6's job - these
    windows just collect user intent.
#>

Set-StrictMode -Version Latest

# Pre-declared (not just assigned on first call) since Set-StrictMode
# -Version Latest forbids even testing ($null -eq / if (-not ...)) a
# $script: variable that was never assigned yet.
$script:MergedXamlDoc = $null
$script:MergedXamlNsMgr = $null

function Get-MergedXamlDocument {
    # Loads AllWindows.Reference.xaml (the app's single source XAML file)
    # once per session and caches the document + an XmlNamespaceManager
    # ready for the SelectSingleNode calls below ('p' = presentation,
    # 'x' = xaml prefixes).
    param([string]$ScriptRoot)
    if (-not $script:MergedXamlDoc) {
        $mergedPath = Join-Path $ScriptRoot 'UI\AllWindows.Reference.xaml'
        $script:MergedXamlDoc = [xml](Get-Content -Raw -Encoding UTF8 $mergedPath)
        $nsMgr = New-Object System.Xml.XmlNamespaceManager($script:MergedXamlDoc.NameTable)
        $nsMgr.AddNamespace('p', 'http://schemas.microsoft.com/winfx/2006/xaml/presentation')
        $nsMgr.AddNamespace('x', 'http://schemas.microsoft.com/winfx/2006/xaml')
        $script:MergedXamlNsMgr = $nsMgr
    }
    return $script:MergedXamlDoc
}

function Import-XamlFragment {
    # Extracts a node from the merged document and loads it as standalone
    # XAML: OuterXml re-serializes the xmlns this node needs (inherited
    # from the root <MergedXamlReference>), so XamlReader.Load gets the
    # same XML as when each window lived in its own file.
    param([System.Xml.XmlNode]$Node)
    [xml]$fragment = $Node.OuterXml
    $reader = New-Object System.Xml.XmlNodeReader $fragment
    return [System.Windows.Markup.XamlReader]::Load($reader)
}

function Get-MergedXamlWindowNode {
    param([string]$ScriptRoot, [Parameter(Mandatory)][string]$Name)
    $doc = Get-MergedXamlDocument -ScriptRoot $ScriptRoot
    $node = $doc.SelectSingleNode("/p:MergedXamlReference/p:Window[@x:Name='$Name']", $script:MergedXamlNsMgr)
    if (-not $node) {
        throw "XAML block '$Name' not found in AllWindows.Reference.xaml"
    }
    return $node
}

function Get-MergedXamlStyleNode {
    param([string]$ScriptRoot)
    $doc = Get-MergedXamlDocument -ScriptRoot $ScriptRoot
    $node = $doc.SelectSingleNode('/p:MergedXamlReference/p:ResourceDictionary', $script:MergedXamlNsMgr)
    if (-not $node) {
        throw "ResourceDictionary block not found in AllWindows.Reference.xaml"
    }
    return $node
}

function Import-XamlWindow {
    # Single entry point for the 9 dialog windows (all except MainWindow.xaml,
    # loaded directly in GpEdit.ps1): applies the Windows 10/11 style (see
    # Styles/ModernStyle.xaml) to all of them here instead of merging the
    # dictionary per window - $script:ModernStyle is the same shared
    # ResourceDictionary as MainWindow's (one ResourceDictionary can be
    # merged into several windows fine).
    param([string]$ScriptRoot, [Parameter(Mandatory)][string]$Name, $Owner)
    $node = Get-MergedXamlWindowNode -ScriptRoot $ScriptRoot -Name $Name
    $win = Import-XamlFragment -Node $node
    if ($Owner) { $win.Owner = $Owner }
    if ($script:ModernStyle) {
        $win.Resources.MergedDictionaries.Add($script:ModernStyle)
        $win.Background = '#F3F3F3'
        $win.FontFamily = 'Segoe UI'
        $win.FontSize = 13
    }
    return $win
}

function New-LabeledControl {
    param([string]$LabelText, [System.Windows.UIElement]$Control)
    $panel = New-Object System.Windows.Controls.StackPanel
    $panel.Margin = '0,0,0,10'
    $label = New-Object System.Windows.Controls.TextBlock
    $label.Text = $LabelText
    $label.Margin = '0,0,0,3'
    $label.FontWeight = 'SemiBold'
    [void]$panel.Children.Add($label)
    [void]$panel.Children.Add($Control)
    return $panel
}

function Add-CisInfoParagraph {
    # Adds a paragraph to a RichTextBox's FlowDocument, bold only if it
    # matches the CIS "recommended state" sentence - the only formatting
    # requested, the rest of the Info text stays normal.
    param([System.Windows.Documents.FlowDocument]$Document, [string]$Text)

    $paragraph = New-Object System.Windows.Documents.Paragraph
    $run = New-Object System.Windows.Documents.Run($Text)
    if ($Text -match '^\s*The recommended state for this setting is\s*:') {
        $run.FontWeight = 'Bold'
    }
    [void]$paragraph.Inlines.Add($run)
    [void]$Document.Blocks.Add($paragraph)
}

function Enable-CatalogFieldEditToggle {
    <#
        Generic wiring for the pencil/Save/Cancel triptych shared by
        SecurityEditWindow's 3 editable fields (Name/Explain/CIS Info):
        toggles between read-only display and an editable textbox, and
        calls $OnSave with the entered text on Save click. $OnSave must
        return $true on success (exit edit mode) or $false to stay in it
        (e.g. error already shown to the user).
    #>
    param(
        [Parameter(Mandatory)]$EditButton,
        [Parameter(Mandatory)]$SaveButton,
        [Parameter(Mandatory)]$CancelButton,
        [Parameter(Mandatory)]$DisplayControl,
        [Parameter(Mandatory)]$EditControl,
        [Parameter(Mandatory)][scriptblock]$GetCurrentText,
        [Parameter(Mandatory)][scriptblock]$OnSave
    )

    # .GetNewClosure() is required here (unlike closures inline in
    # Show-SecurityEditDialog): this function returns BEFORE clicks happen,
    # so its parameter scope (EditControl, etc.) no longer exists on the
    # call stack when the WPF event fires - without explicit capture,
    # PowerShell would try to resolve these variables in whatever scope is
    # active then (the WPF message loop), where they don't exist ->
    # "variable not defined" under Set-StrictMode. Show-SecurityEditDialog
    # stays on the stack the whole time $window.ShowDialog() blocks, so its
    # inline closures don't need GetNewClosure().
    $EditButton.Add_Click({
        $EditControl.Text = & $GetCurrentText
        $DisplayControl.Visibility = 'Collapsed'
        $EditControl.Visibility = 'Visible'
        $EditButton.Visibility = 'Collapsed'
        $SaveButton.Visibility = 'Visible'
        $CancelButton.Visibility = 'Visible'
        $EditControl.Focus() | Out-Null
    }.GetNewClosure())

    $CancelButton.Add_Click({
        $DisplayControl.Visibility = 'Visible'
        $EditControl.Visibility = 'Collapsed'
        $EditButton.Visibility = 'Visible'
        $SaveButton.Visibility = 'Collapsed'
        $CancelButton.Visibility = 'Collapsed'
    }.GetNewClosure())

    $SaveButton.Add_Click({
        $saved = & $OnSave $EditControl.Text
        if ($saved) {
            $DisplayControl.Visibility = 'Visible'
            $EditControl.Visibility = 'Collapsed'
            $EditButton.Visibility = 'Visible'
            $SaveButton.Visibility = 'Collapsed'
            $CancelButton.Visibility = 'Collapsed'
        }
    }.GetNewClosure())
}

function Get-CisClientEditionRoleClass {
    <#
        Classifies a client OS benchmark name (Windows 10/11) as
        'StandAlone' or 'Enterprise' - drives how ConvertTo-CisProfileRows
        fills the DC/MS columns for these benchmarks, which have no real
        DC/MS role in the CIS sense (role = $null in the index). $null for
        any Server benchmark (real DC/MS role, derived from data) or an
        unrecognized benchmark name.

        User decision (2026-07-27): "Enterprise" represents a domain-joined
        managed workstation - treated as a domain member, i.e. equivalent
        to an MS role (DC=No, MS=Yes). "Stand-alone" is off-domain, with no
        role equivalent at all (DC=MS="-").
    #>
    param([string]$Benchmark)

    if ($Benchmark -notmatch 'Windows\s*1[01]\b') { return $null }
    if ($Benchmark -match 'Stand-alone') { return 'StandAlone' }
    if ($Benchmark -match 'Enterprise') { return 'Enterprise' }
    return $null
}

function Get-CisRoleColumnsForRow {
    <#
        Computes the DC/MS columns for a REAL row (a recommendation exists
        for this exact benchmark+version+level) - see
        ConvertTo-CisProfileRows, which only shows real rows (2026-07-27
        rollback: no more filler rows for benchmarks without a
        recommendation, including "Stand-alone").
    #>
    param([string]$Benchmark, [string[]]$Roles, [hashtable]$Ui)

    $editionClass = Get-CisClientEditionRoleClass -Benchmark $Benchmark
    if ($editionClass -eq 'StandAlone') {
        return @{ Dc = $Ui.CisNotApplicable; Ms = $Ui.CisNotApplicable }
    }
    if ($editionClass -eq 'Enterprise') {
        return @{ Dc = $Ui.CisNo; Ms = $Ui.CisYes }
    }
    return @{
        Dc = if ($Roles -contains 'DC') { $Ui.CisYes } else { $Ui.CisNo }
        Ms = if ($Roles -contains 'MS') { $Ui.CisYes } else { $Ui.CisNo }
    }
}

function ConvertTo-CisProfileRows {
    <#
        Turns the raw profiles[] list (benchmark/version/level/role/
        cisNumber/valueData) from the CIS index into DataGrid-ready
        objects, with the localized "or" word replacing the "||" separator.

        One row per (benchmark, version, level, cisNumber, valueData) -
        Benchmark and Version in separate columns (a benchmark can have
        several versions), Profile holds only L1/L2, and DC/MS are two
        Yes/No columns ("-" for "Stand-alone") showing which role(s) this
        number+value applies to (when MS and DC share the same
        number/value, one row has DC=Yes and MS=Yes; when they diverge, two
        separate rows appear, each with a single Yes).
    #>
    param($Profiles, [hashtable]$Ui)

    $rows = New-Object System.Collections.Generic.List[object]
    $groups = @($Profiles) | Group-Object -Property { "$($_.benchmark)|$($_.version)|$($_.level)|$($_.cisNumber)|$($_.valueData)" }
    foreach ($g in $groups) {
        $first = $g.Group[0]
        $roles = @($g.Group.role | Select-Object -Unique)
        $columns = Get-CisRoleColumnsForRow -Benchmark $first.benchmark -Roles $roles -Ui $Ui

        $valueData = if ($first.valueData) { ($first.valueData -replace '\s*\|\|\s*', " $($Ui.CisOrWord) ") } else { $first.valueData }
        $rows.Add([pscustomobject]@{
            Benchmark = $first.benchmark
            Version   = $first.version
            Profile   = $first.level
            Dc        = $columns.Dc
            Ms        = $columns.Ms
            CisNumber = $first.cisNumber
            ValueData = $valueData
            SortYear  = Get-CisBenchmarkYear -Benchmark $first.benchmark
        })
    }

    return [System.Collections.Generic.List[object]]@(
        $rows | Sort-Object -Property @(
            @{ Expression = 'SortYear'; Descending = $true },
            @{ Expression = 'Benchmark'; Descending = $false },
            @{ Expression = 'Version'; Descending = $true },
            @{ Expression = 'Profile'; Descending = $false }
        ) | Select-Object Benchmark, Version, Profile, Dc, Ms, CisNumber, ValueData
    )
}

function Set-CisRecommendationTab {
    <#
        Populates (or hides) the "CIS recommendation" tab shared by
        AdmxEditWindow.xaml and SecurityEditWindow.xaml. $RegKeyControls is
        $null for SecurityEditWindow (no reg_key/reg_item for
        security/advanced-audit settings).
    #>
    param(
        $CisRecommendation,
        [Parameter(Mandatory)]$CisTabItem,
        [Parameter(Mandatory)]$CisDescriptionLabel,
        [Parameter(Mandatory)]$CisInfoRichTextBox,
        [Parameter(Mandatory)]$CisValueTypeLabel,
        [Parameter(Mandatory)]$CisProfilesGrid,
        $RegKeyHeaderLabel,
        $RegKeyLabel,
        $RegItemHeaderLabel,
        $RegItemLabel,
        [Parameter(Mandatory)][hashtable]$Ui
    )

    if ($null -eq $CisRecommendation) {
        $CisTabItem.Visibility = 'Collapsed'
        return
    }

    $CisTabItem.Visibility = 'Visible'
    $CisDescriptionLabel.Text = $CisRecommendation.title
    $CisValueTypeLabel.Text = $CisRecommendation.valueType

    $doc = New-Object System.Windows.Documents.FlowDocument
    foreach ($paragraphText in ($CisRecommendation.info -split "`n`n")) {
        Add-CisInfoParagraph -Document $doc -Text $paragraphText
    }
    $CisInfoRichTextBox.Document = $doc

    if ($RegKeyLabel) {
        $hasRegistry = -not [string]::IsNullOrEmpty($CisRecommendation.regKey)
        $RegKeyHeaderLabel.Visibility = if ($hasRegistry) { 'Visible' } else { 'Collapsed' }
        $RegKeyLabel.Visibility = if ($hasRegistry) { 'Visible' } else { 'Collapsed' }
        $RegItemHeaderLabel.Visibility = if ($hasRegistry) { 'Visible' } else { 'Collapsed' }
        $RegItemLabel.Visibility = if ($hasRegistry) { 'Visible' } else { 'Collapsed' }
        $RegKeyLabel.Text = $CisRecommendation.regKey
        $RegItemLabel.Text = $CisRecommendation.regItem
    }

    # @() is needed here: ConvertTo-CisProfileRows returns a List[object]
    # via "return", which PowerShell unwraps to a single object (not
    # IEnumerable, crashes on ItemsSource) once it holds just one row.
    $CisProfilesGrid.ItemsSource = @(ConvertTo-CisProfileRows -Profiles $CisRecommendation.profiles -Ui $Ui)
}

function Show-AdmxEditDialog {
    param(
        [Parameter(Mandatory)]$Policy,
        [Parameter(Mandatory)][string]$CurrentState,
        [hashtable]$CurrentElementValues = @{},
        $CisRecommendation,
        $Owner,
        [string]$ScriptRoot,
        [Parameter(Mandatory)][hashtable]$Ui
    )

    $window = Import-XamlWindow -ScriptRoot $ScriptRoot -Name 'AdmxEditWindow' -Owner $Owner

    $titleLabel        = $window.FindName('TitleLabel')
    $categoryPathLabel = $window.FindName('CategoryPathLabel')
    $notConfiguredRadio = $window.FindName('NotConfiguredRadio')
    $enabledRadio      = $window.FindName('EnabledRadio')
    $disabledRadio     = $window.FindName('DisabledRadio')
    $elementsPanel     = $window.FindName('ElementsPanel')
    $explainGroupBox   = $window.FindName('ExplainGroupBox')
    $explainTextBlock  = $window.FindName('ExplainTextBlock')
    $supportedOnLabel  = $window.FindName('SupportedOnLabel')
    $okButton          = $window.FindName('OkButton')
    $cancelButton      = $window.FindName('CancelButton')
    $settingTabItem    = $window.FindName('SettingTabItem')
    $cisTabItem        = $window.FindName('CisTabItem')
    $cisDescriptionHeaderLabel = $window.FindName('CisDescriptionHeaderLabel')
    $cisDescriptionLabel = $window.FindName('CisDescriptionLabel')
    $cisInfoHeaderLabel = $window.FindName('CisInfoHeaderLabel')
    $cisInfoRichTextBox = $window.FindName('CisInfoRichTextBox')
    $cisValueTypeHeaderLabel = $window.FindName('CisValueTypeHeaderLabel')
    $cisValueTypeLabel = $window.FindName('CisValueTypeLabel')
    $cisRegKeyHeaderLabel = $window.FindName('CisRegKeyHeaderLabel')
    $cisRegKeyLabel    = $window.FindName('CisRegKeyLabel')
    $cisRegItemHeaderLabel = $window.FindName('CisRegItemHeaderLabel')
    $cisRegItemLabel   = $window.FindName('CisRegItemLabel')
    $cisProfilesHeaderLabel = $window.FindName('CisProfilesHeaderLabel')
    $cisProfilesGrid   = $window.FindName('CisProfilesGrid')

    $window.Title = $Ui.DialogTitleAdmxDefault
    $notConfiguredRadio.Content = $Ui.RadioNotConfigured
    $enabledRadio.Content = $Ui.RadioEnabled
    $disabledRadio.Content = $Ui.RadioDisabled
    $explainGroupBox.Header = $Ui.ExplanationHeader
    $okButton.Content = $Ui.OkButton
    $cancelButton.Content = $Ui.CancelButton
    $settingTabItem.Header = $Ui.SettingTabHeader
    $cisTabItem.Header = $Ui.CisTabHeader
    $cisDescriptionHeaderLabel.Text = 'Description'
    $cisInfoHeaderLabel.Text = 'Info'
    $cisValueTypeHeaderLabel.Text = 'Value Type'
    $cisRegKeyHeaderLabel.Text = 'Reg Key'
    $cisRegItemHeaderLabel.Text = 'Reg Item'
    $cisProfilesHeaderLabel.Text = $Ui.CisProfilesHeader
    $window.FindName('CisProfilesBenchmarkColumn').Header = $Ui.CisProfileColumnBenchmark
    $window.FindName('CisProfilesVersionColumn').Header = $Ui.CisProfileColumnVersion
    $window.FindName('CisProfilesProfileColumn').Header = $Ui.CisProfileColumnProfile
    $window.FindName('CisProfilesDcColumn').Header = $Ui.CisProfileColumnDc
    $window.FindName('CisProfilesMsColumn').Header = $Ui.CisProfileColumnMs
    $window.FindName('CisProfilesNumberColumn').Header = $Ui.CisProfileColumnNumber
    $window.FindName('CisProfilesValueColumn').Header = $Ui.CisProfileColumnValue

    $titleLabel.Text = $Policy.displayName
    $categoryPathLabel.Text = $Policy.categoryPathText
    Set-ExplainTextWithDefaultHighlight -TextBlock $explainTextBlock -Text $Policy.explainText
    $supportedOnLabel.Text = "$($Ui.SupportedOnPrefix)$($Policy.supportedOnText)"

    Set-CisRecommendationTab -CisRecommendation $CisRecommendation -CisTabItem $cisTabItem `
        -CisDescriptionLabel $cisDescriptionLabel -CisInfoRichTextBox $cisInfoRichTextBox `
        -CisValueTypeLabel $cisValueTypeLabel -CisProfilesGrid $cisProfilesGrid `
        -RegKeyHeaderLabel $cisRegKeyHeaderLabel -RegKeyLabel $cisRegKeyLabel `
        -RegItemHeaderLabel $cisRegItemHeaderLabel -RegItemLabel $cisRegItemLabel -Ui $Ui

    switch ($CurrentState) {
        'Enabled'  { $enabledRadio.IsChecked = $true }
        'Disabled' { $disabledRadio.IsChecked = $true }
        default    { $notConfiguredRadio.IsChecked = $true }
    }

    # --- Dynamic control creation per element type ---
    $elementControls = @{}
    foreach ($el in @($Policy.elements)) {
        $currentValue = $null
        if ($CurrentElementValues.ContainsKey($el.id)) { $currentValue = $CurrentElementValues[$el.id] }
        # Localized label from the ADML presentation (Get-AdmlPresentationLabelMap
        # in Build-AdmxIndex.ps1); falls back to the raw ADMX id if missing
        # (e.g. presentation not found/malformed).
        $labelText = if ($el.label) { $el.label } else { $el.id }
        if ($el.required) { $labelText += $Ui.RequiredSuffix }

        switch ($el.type) {
            'boolean' {
                $chk = New-Object System.Windows.Controls.CheckBox
                $chk.Content = $labelText
                $chk.Margin = '0,0,0,10'
                if ($null -ne $currentValue) { $chk.IsChecked = [bool]$currentValue }
                [void]$elementsPanel.Children.Add($chk)
                $elementControls[$el.id] = @{ Type = 'boolean'; Control = $chk }
            }
            'enum' {
                $combo = New-Object System.Windows.Controls.ComboBox
                foreach ($it in @($el.items)) {
                    $cbi = New-Object System.Windows.Controls.ComboBoxItem
                    $cbi.Content = $it.displayName
                    $cbi.Tag = $it.value
                    [void]$combo.Items.Add($cbi)
                    if ($null -ne $currentValue -and "$($it.value)" -eq "$currentValue") { $combo.SelectedItem = $cbi }
                }
                if ($combo.SelectedIndex -lt 0 -and $combo.Items.Count -gt 0) { $combo.SelectedIndex = 0 }
                [void]$elementsPanel.Children.Add((New-LabeledControl -LabelText $labelText -Control $combo))
                $elementControls[$el.id] = @{ Type = 'enum'; Control = $combo }
            }
            'decimal' {
                $tb = New-Object System.Windows.Controls.TextBox
                $tb.Text = if ($null -ne $currentValue) { "$currentValue" } else { "$($el.defaultValue)" }
                $hint = "$labelText"
                if ($el.minValue -or $el.maxValue) { $hint += " (entre $($el.minValue) et $($el.maxValue))" }
                [void]$elementsPanel.Children.Add((New-LabeledControl -LabelText $hint -Control $tb))
                $elementControls[$el.id] = @{ Type = 'decimal'; Control = $tb }
            }
            'text' {
                $tb = New-Object System.Windows.Controls.TextBox
                $tb.Text = if ($null -ne $currentValue) { "$currentValue" } else { "$($el.defaultValue)" }
                [void]$elementsPanel.Children.Add((New-LabeledControl -LabelText $labelText -Control $tb))
                $elementControls[$el.id] = @{ Type = 'text'; Control = $tb }
            }
            { $_ -in 'multiText', 'list' } {
                $tb = New-Object System.Windows.Controls.TextBox
                $tb.AcceptsReturn = $true
                $tb.Height = 90
                $tb.TextWrapping = 'NoWrap'
                $tb.VerticalScrollBarVisibility = 'Auto'
                if ($currentValue -is [array]) { $tb.Text = ($currentValue -join "`r`n") }
                [void]$elementsPanel.Children.Add((New-LabeledControl -LabelText "$labelText$($Ui.MultiValueHint)" -Control $tb))
                $elementControls[$el.id] = @{ Type = $el.type; Control = $tb }
            }
        }
    }

    $updatePanelEnabled = {
        $elementsPanel.IsEnabled = ($enabledRadio.IsChecked -eq $true)
    }
    $notConfiguredRadio.Add_Checked($updatePanelEnabled)
    $enabledRadio.Add_Checked($updatePanelEnabled)
    $disabledRadio.Add_Checked($updatePanelEnabled)
    & $updatePanelEnabled

    $script:__admxDialogResult = $null

    $okButton.Add_Click({
        $state = if ($enabledRadio.IsChecked) { 'Enabled' } elseif ($disabledRadio.IsChecked) { 'Disabled' } else { 'NotConfigured' }

        $values = @{}
        if ($state -eq 'Enabled') {
            foreach ($id in $elementControls.Keys) {
                $ctrl = $elementControls[$id]
                switch ($ctrl.Type) {
                    'boolean' { $values[$id] = [bool]$ctrl.Control.IsChecked }
                    'enum' {
                        if ($ctrl.Control.SelectedItem) { $values[$id] = $ctrl.Control.SelectedItem.Tag }
                    }
                    'decimal' {
                        $n = 0
                        if (-not [int]::TryParse($ctrl.Control.Text, [ref]$n)) {
                            [System.Windows.MessageBox]::Show(($Ui.InvalidNumberMessage -f $id), $Ui.ErrorTitle, 'OK', 'Warning') | Out-Null
                            return
                        }
                        $values[$id] = $n
                    }
                    'text' { $values[$id] = $ctrl.Control.Text }
                    default {
                        $lines = @($ctrl.Control.Text -split "`r`n|`n" | Where-Object { $_ -ne '' })
                        $values[$id] = $lines
                    }
                }
            }
        }

        $script:__admxDialogResult = @{ State = $state; ElementValues = $values }
        $window.DialogResult = $true
        $window.Close()
    })

    $cancelButton.Add_Click({
        $window.DialogResult = $false
        $window.Close()
    })

    $null = $window.ShowDialog()
    return $script:__admxDialogResult
}

function Set-ExplainTextWithDefaultHighlight {
    <#
        Builds a TextBlock's Inlines from an arbitrary Explain text: any
        line starting with "Default"/"Defaults" followed (before the next
        line break) by ":" - "Default:", "Default Value:", "Default on
        domain controllers:", etc. - is bolded + blue (color matches
        AccentBrush in ModernStyle.xaml), rest stays normal. The catalog
        (SecurityCatalog.ps1) doesn't use one fixed wording for these
        lines, hence the regex instead of a literal StartsWith('Default:')
        which missed most variants. Used everywhere an explanation is
        shown - Security Options' inline "Explain" tab, the classic
        "Explain" tab for other security categories, and AdmxEditWindow's
        ExplainGroupBox - not limited to one context despite the name.
    #>
    param([Parameter(Mandatory)]$TextBlock, [string]$Text)

    $TextBlock.Inlines.Clear()
    if (-not $Text) { return }

    $accentBrush = New-Object System.Windows.Media.SolidColorBrush(
        [System.Windows.Media.ColorConverter]::ConvertFromString('#0067C0'))

    $lines = @($Text -split "\r?\n")
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        $run = New-Object System.Windows.Documents.Run($line)
        if ($line.TrimStart() -match '^Defaults?\b.*:') {
            $run.FontWeight = 'Bold'
            $run.Foreground = $accentBrush
        }
        $TextBlock.Inlines.Add($run)
        if ($i -lt $lines.Count - 1) { $TextBlock.Inlines.Add((New-Object System.Windows.Documents.LineBreak)) }
    }
}

function Show-SecurityEditDialog {
    param(
        [Parameter(Mandatory)]$Setting,
        $CisRecommendation,
        $Owner,
        [string]$ScriptRoot,
        [Parameter(Mandatory)][hashtable]$Ui,
        [string]$DataPath
    )

    $window = Import-XamlWindow -ScriptRoot $ScriptRoot -Name 'SecurityEditWindow' -Owner $Owner

    # Signals to the caller (GpEdit.ps1) that at least one catalog edit
    # (Name/Explain) was saved - independent of $script:__secDialogResult
    # (the classic OK/Cancel setting value): the caller must refresh the
    # security index/list even if the window is later closed via Cancel,
    # since these edits are already written to disk.
    $script:__secDialogCatalogEdited = $false

    $titleLabel       = $window.FindName('TitleLabel')
    $descriptionLabel = $window.FindName('DescriptionLabel')
    $isConfiguredCheck = $window.FindName('IsConfiguredCheck')
    $valueEditorPanel = $window.FindName('ValueEditorPanel')
    $okButton         = $window.FindName('OkButton')
    $cancelButton     = $window.FindName('CancelButton')
    $settingTabItem   = $window.FindName('SettingTabItem')
    $explainTabItem   = $window.FindName('ExplainTabItem')
    $explainTextBlock = $window.FindName('ExplainTextBlock')
    $cisTabItem       = $window.FindName('CisTabItem')
    $cisDescriptionHeaderLabel = $window.FindName('CisDescriptionHeaderLabel')
    $cisDescriptionLabel = $window.FindName('CisDescriptionLabel')
    $cisInfoHeaderLabel = $window.FindName('CisInfoHeaderLabel')
    $cisInfoRichTextBox = $window.FindName('CisInfoRichTextBox')
    $cisValueTypeHeaderLabel = $window.FindName('CisValueTypeHeaderLabel')
    $cisValueTypeLabel = $window.FindName('CisValueTypeLabel')
    $cisProfilesHeaderLabel = $window.FindName('CisProfilesHeaderLabel')
    $cisProfilesGrid  = $window.FindName('CisProfilesGrid')

    # Live catalog editor (Name/Explain/CIS Info).
    $nameEditButtonsPanel    = $window.FindName('NameEditButtonsPanel')
    $editNameButton          = $window.FindName('EditNameButton')
    $saveNameButton          = $window.FindName('SaveNameButton')
    $cancelNameButton        = $window.FindName('CancelNameButton')
    $explainTabHeaderText    = $window.FindName('ExplainTabHeaderText')
    $explainEditButtonsPanel = $window.FindName('ExplainEditButtonsPanel')
    $editExplainButton       = $window.FindName('EditExplainButton')
    $saveExplainButton       = $window.FindName('SaveExplainButton')
    $cancelExplainButton     = $window.FindName('CancelExplainButton')
    $explainDisplayScroll    = $window.FindName('ExplainDisplayScroll')
    $explainEditTextBox      = $window.FindName('ExplainEditTextBox')

    # Inline explanation on the Setting tab, Security Options only -
    # replaces ExplainTabItem for this category, others keep the separate tab.
    $inlineExplainGroupBox        = $window.FindName('InlineExplainGroupBox')
    $inlineExplainHeaderText      = $window.FindName('InlineExplainHeaderText')
    $inlineExplainEditButtonsPanel = $window.FindName('InlineExplainEditButtonsPanel')
    $editInlineExplainButton      = $window.FindName('EditInlineExplainButton')
    $saveInlineExplainButton      = $window.FindName('SaveInlineExplainButton')
    $cancelInlineExplainButton    = $window.FindName('CancelInlineExplainButton')
    $inlineExplainDisplayScroll   = $window.FindName('InlineExplainDisplayScroll')
    $inlineExplainTextBlock       = $window.FindName('InlineExplainTextBlock')
    $inlineExplainEditTextBox     = $window.FindName('InlineExplainEditTextBox')

    $cisInfoEditButtonsPanel = $window.FindName('CisInfoEditButtonsPanel')
    $editCisInfoButton       = $window.FindName('EditCisInfoButton')
    $saveCisInfoButton       = $window.FindName('SaveCisInfoButton')
    $cancelCisInfoButton     = $window.FindName('CancelCisInfoButton')
    $cisInfoEditTextBox      = $window.FindName('CisInfoEditTextBox')

    $window.Title = $Ui.DialogTitleSecurityDefault
    $isConfiguredCheck.Content = $Ui.DefineThisSetting
    $okButton.Content = $Ui.OkButton
    $cancelButton.Content = $Ui.CancelButton
    $settingTabItem.Header = $Ui.SettingTabHeader
    $explainTabHeaderText.Text = $Ui.ExplainTabHeader
    $inlineExplainHeaderText.Text = $Ui.ExplainTabHeader
    $cisTabItem.Header = $Ui.CisTabHeader
    $cisDescriptionHeaderLabel.Text = 'Description'
    $cisInfoHeaderLabel.Text = 'Info'
    $cisValueTypeHeaderLabel.Text = 'Value Type'
    $cisProfilesHeaderLabel.Text = $Ui.CisProfilesHeader
    $window.FindName('CisProfilesBenchmarkColumn').Header = $Ui.CisProfileColumnBenchmark
    $window.FindName('CisProfilesVersionColumn').Header = $Ui.CisProfileColumnVersion
    $window.FindName('CisProfilesProfileColumn').Header = $Ui.CisProfileColumnProfile
    $window.FindName('CisProfilesDcColumn').Header = $Ui.CisProfileColumnDc
    $window.FindName('CisProfilesMsColumn').Header = $Ui.CisProfileColumnMs
    $window.FindName('CisProfilesNumberColumn').Header = $Ui.CisProfileColumnNumber
    $window.FindName('CisProfilesValueColumn').Header = $Ui.CisProfileColumnValue
    foreach ($btn in @($editNameButton, $editExplainButton, $editInlineExplainButton, $editCisInfoButton)) { $btn.ToolTip = $Ui.EditFieldButtonTooltip }
    foreach ($btn in @($saveNameButton, $saveExplainButton, $saveInlineExplainButton, $saveCisInfoButton)) { $btn.Content = $Ui.SaveFieldButton }
    foreach ($btn in @($cancelNameButton, $cancelExplainButton, $cancelInlineExplainButton, $cancelCisInfoButton)) { $btn.Content = $Ui.CancelButton }

    $titleLabel.Text = $Setting.displayName
    $descriptionLabel.Text = $Setting.description
    $isConfiguredCheck.IsChecked = $Setting.isConfigured

    # LegalNoticeCaption/LegalNoticeText (Security Options): per explicit
    # user decision, these settings must always stay configured - checkbox
    # checked and locked (Build-SecurityIndex.ps1 already forces
    # isConfigured=$true on the data side; this also blocks unchecking in
    # the UI).
    if ($Setting.PSObject.Properties['alwaysConfigured'] -and $Setting.alwaysConfigured) {
        $isConfiguredCheck.IsChecked = $true
        $isConfiguredCheck.IsEnabled = $false
    }

    # Security Options shows the explanation directly on the Setting tab
    # (like Administrative Templates); all other categories keep the
    # separate Explain tab unchanged - explicit user decision, not a
    # general simplification.
    $isSecurityOptionsExplain = ($Setting.category -eq 'Security Options')
    $explainTabItem.Visibility = if ($isSecurityOptionsExplain) { 'Collapsed' } else { 'Visible' }
    $inlineExplainGroupBox.Visibility = if ($isSecurityOptionsExplain) { 'Visible' } else { 'Collapsed' }
    $initialExplainText = if ($Setting.explain) { $Setting.explain } else { $Setting.description }
    if ($isSecurityOptionsExplain) {
        Set-ExplainTextWithDefaultHighlight -TextBlock $inlineExplainTextBlock -Text $initialExplainText
    } else {
        Set-ExplainTextWithDefaultHighlight -TextBlock $explainTextBlock -Text $initialExplainText
    }

    # $Setting comes from security-index.<lang>.json (SecurityCatalog.ps1
    # settings) or advanced-audit-index.<lang>.json (AdvancedAuditCatalog.ps1,
    # never editable here - out of scope): only the former has
    # section/catalogKey fields. Checked via PSObject.Properties, not plain
    # $Setting.section, to avoid crashing under Set-StrictMode when the
    # property doesn't exist on the object at all.
    $catalogVarForSetting = $null
    if ($Setting.PSObject.Properties['section'] -and $Setting.PSObject.Properties['catalogKey']) {
        $catalogVarForSetting = Get-SecurityCatalogVariableName -Category $Setting.category -Section $Setting.section
    }
    $canEditNameExplain = $script:CatalogEditingEnabled -and $catalogVarForSetting

    $canEditCisInfo = $script:CatalogEditingEnabled -and $CisRecommendation -and
        $CisRecommendation.PSObject.Properties['bucket'] -and $CisRecommendation.PSObject.Properties['key']

    if ($canEditNameExplain) {
        # TitleLabel doubles as display and edit control (already a
        # read-only TextBox): no second control to swap like for
        # Explain/CIS Info, so no Enable-CatalogFieldEditToggle here - just
        # toggle IsReadOnly, keeping the original text to restore on Cancel.
        $catalogPath = Join-Path $ScriptRoot 'Catalogs\SecurityCatalog.ps1'
        $originalNameText = $null

        $editNameButton.Add_Click({
            $originalNameText = $titleLabel.Text
            $titleLabel.IsReadOnly = $false
            $titleLabel.IsReadOnlyCaretVisible = $true
            $titleLabel.Background = 'White'
            $titleLabel.BorderThickness = '1'
            $editNameButton.Visibility = 'Collapsed'
            $saveNameButton.Visibility = 'Visible'
            $cancelNameButton.Visibility = 'Visible'
            $titleLabel.Focus() | Out-Null
            $titleLabel.SelectAll()
        })

        $cancelNameButton.Add_Click({
            $titleLabel.Text = $originalNameText
            $titleLabel.IsReadOnly = $true
            $titleLabel.IsReadOnlyCaretVisible = $false
            $titleLabel.Background = 'Transparent'
            $titleLabel.BorderThickness = '0'
            $editNameButton.Visibility = 'Visible'
            $saveNameButton.Visibility = 'Collapsed'
            $cancelNameButton.Visibility = 'Collapsed'
        })

        $saveNameButton.Add_Click({
            $newText = $titleLabel.Text
            if ([string]::IsNullOrWhiteSpace($newText)) { return }
            try {
                Set-SecurityCatalogEntryField -Path $catalogPath -Category $Setting.category -Section $Setting.section `
                    -CatalogKey $Setting.catalogKey -Field 'DisplayName' -Text $newText
                . $catalogPath
                $Setting.displayName = $newText
                $script:__secDialogCatalogEdited = $true
                $titleLabel.IsReadOnly = $true
                $titleLabel.IsReadOnlyCaretVisible = $false
                $titleLabel.Background = 'Transparent'
                $titleLabel.BorderThickness = '0'
                $editNameButton.Visibility = 'Visible'
                $saveNameButton.Visibility = 'Collapsed'
                $cancelNameButton.Visibility = 'Collapsed'
            }
            catch {
                [System.Windows.MessageBox]::Show(($Ui.CatalogFieldSaveErrorFormat -f $_.Exception.Message), $Ui.ErrorTitle, 'OK', 'Warning') | Out-Null
            }
        })
    }
    else {
        $nameEditButtonsPanel.Visibility = 'Collapsed'
    }

    if ($canEditNameExplain -and -not $isSecurityOptionsExplain) {
        $catalogPath = Join-Path $ScriptRoot 'Catalogs\SecurityCatalog.ps1'

        # $explainTextBlock.Text isn't enough (same reason as
        # Set-ExplainTextWithDefaultHighlight above - a TextBlock filled via
        # Inlines returns an empty string from its .Text getter): use a
        # TextRange instead, like the inline Security Options tab.
        Enable-CatalogFieldEditToggle -EditButton $editExplainButton -SaveButton $saveExplainButton -CancelButton $cancelExplainButton `
            -DisplayControl $explainDisplayScroll -EditControl $explainEditTextBox -GetCurrentText {
                $range = New-Object System.Windows.Documents.TextRange($explainTextBlock.ContentStart, $explainTextBlock.ContentEnd)
                $range.Text -replace "`r`n", "`n"
            } -OnSave {
                param($newText)
                if ([string]::IsNullOrWhiteSpace($newText)) { return $false }
                try {
                    Set-SecurityCatalogEntryField -Path $catalogPath -Category $Setting.category -Section $Setting.section `
                        -CatalogKey $Setting.catalogKey -Field 'Explain' -Text $newText
                    . $catalogPath
                    Set-ExplainTextWithDefaultHighlight -TextBlock $explainTextBlock -Text $newText
                    $Setting.explain = $newText
                    $script:__secDialogCatalogEdited = $true
                    return $true
                }
                catch {
                    [System.Windows.MessageBox]::Show(($Ui.CatalogFieldSaveErrorFormat -f $_.Exception.Message), $Ui.ErrorTitle, 'OK', 'Warning') | Out-Null
                    return $false
                }
            }
        $inlineExplainEditButtonsPanel.Visibility = 'Collapsed'
        $editInlineExplainButton.Visibility = 'Collapsed'
    }
    elseif ($canEditNameExplain -and $isSecurityOptionsExplain) {
        $catalogPath = Join-Path $ScriptRoot 'Catalogs\SecurityCatalog.ps1'

        # $inlineExplainTextBlock.Text does NOT work here (verified by an
        # isolated test on the actual displayed window): unlike a directly
        # assigned TextBlock.Text (classic Explain tab), a TextBlock filled
        # via Inlines (Run/LineBreak, see Set-ExplainTextWithDefaultHighlight)
        # returns an EMPTY string from its .Text getter - must use a
        # TextRange on ContentStart/ContentEnd instead, which yields the
        # real text (LineBreak -> `r`n, normalized to `n to match the
        # catalog format).
        Enable-CatalogFieldEditToggle -EditButton $editInlineExplainButton -SaveButton $saveInlineExplainButton -CancelButton $cancelInlineExplainButton `
            -DisplayControl $inlineExplainDisplayScroll -EditControl $inlineExplainEditTextBox -GetCurrentText {
                $range = New-Object System.Windows.Documents.TextRange($inlineExplainTextBlock.ContentStart, $inlineExplainTextBlock.ContentEnd)
                $range.Text -replace "`r`n", "`n"
            } -OnSave {
                param($newText)
                if ([string]::IsNullOrWhiteSpace($newText)) { return $false }
                try {
                    Set-SecurityCatalogEntryField -Path $catalogPath -Category $Setting.category -Section $Setting.section `
                        -CatalogKey $Setting.catalogKey -Field 'Explain' -Text $newText
                    . $catalogPath
                    Set-ExplainTextWithDefaultHighlight -TextBlock $inlineExplainTextBlock -Text $newText
                    $Setting.explain = $newText
                    $script:__secDialogCatalogEdited = $true
                    return $true
                }
                catch {
                    [System.Windows.MessageBox]::Show(($Ui.CatalogFieldSaveErrorFormat -f $_.Exception.Message), $Ui.ErrorTitle, 'OK', 'Warning') | Out-Null
                    return $false
                }
            }
        $explainEditButtonsPanel.Visibility = 'Collapsed'
        $editExplainButton.Visibility = 'Collapsed'
    }
    else {
        $explainEditButtonsPanel.Visibility = 'Collapsed'
        $inlineExplainEditButtonsPanel.Visibility = 'Collapsed'
        $editExplainButton.Visibility = 'Collapsed'
        $editInlineExplainButton.Visibility = 'Collapsed'
    }

    if ($canEditCisInfo) {
        Enable-CatalogFieldEditToggle -EditButton $editCisInfoButton -SaveButton $saveCisInfoButton -CancelButton $cancelCisInfoButton `
            -DisplayControl $cisInfoRichTextBox -EditControl $cisInfoEditTextBox -GetCurrentText { $CisRecommendation.info } -OnSave {
                param($newText)
                if ([string]::IsNullOrWhiteSpace($newText)) { return $false }
                try {
                    Set-CisOverride -DataPath $DataPath -Bucket $CisRecommendation.bucket -Key $CisRecommendation.key -Info $newText
                    # $CisRecommendation is the same object instance stored
                    # in $script:CisIndex (returned by reference by
                    # Get-CisRecommendationFor... - see CisCatalog.ps1):
                    # mutating it here is enough to reflect the change
                    # everywhere, both in this window and the main window,
                    # without rebuilding or reloading anything.
                    $CisRecommendation.info = $newText
                    $doc = New-Object System.Windows.Documents.FlowDocument
                    foreach ($paragraphText in ($newText -split "`n`n")) { Add-CisInfoParagraph -Document $doc -Text $paragraphText }
                    $cisInfoRichTextBox.Document = $doc
                    return $true
                }
                catch {
                    [System.Windows.MessageBox]::Show(($Ui.CatalogFieldSaveErrorFormat -f $_.Exception.Message), $Ui.ErrorTitle, 'OK', 'Warning') | Out-Null
                    return $false
                }
            }
    }
    else {
        $cisInfoEditButtonsPanel.Visibility = 'Collapsed'
    }

    Set-CisRecommendationTab -CisRecommendation $CisRecommendation -CisTabItem $cisTabItem `
        -CisDescriptionLabel $cisDescriptionLabel -CisInfoRichTextBox $cisInfoRichTextBox `
        -CisValueTypeLabel $cisValueTypeLabel -CisProfilesGrid $cisProfilesGrid -Ui $Ui

    $control = $null
    $auditLabels = @($Ui.AuditNone, $Ui.AuditSuccess, $Ui.AuditFailure, $Ui.AuditSuccessFailure)

    switch ($Setting.valueType) {
        'boolean' {
            $control = New-Object System.Windows.Controls.ComboBox
            foreach ($opt in @($Ui.StateDisabled, $Ui.StateEnabled)) { [void]$control.Items.Add($opt) }
            $control.SelectedIndex = if ($Setting.rawValue -eq '1') { 1 } else { 0 }
        }
        'audit' {
            $control = New-Object System.Windows.Controls.ComboBox
            foreach ($opt in $auditLabels) { [void]$control.Items.Add($opt) }
            $idx = 0
            if ($Setting.rawValue) { [int]::TryParse($Setting.rawValue, [ref]$idx) | Out-Null }
            $control.SelectedIndex = [Math]::Min([Math]::Max($idx, 0), 3)
        }
        'minutes-or-forever' {
            $panel = New-Object System.Windows.Controls.StackPanel
            $tb = New-Object System.Windows.Controls.TextBox
            $tb.Width = 100
            $tb.HorizontalAlignment = 'Left'
            $forever = ($Setting.rawValue -eq '-1')
            $tb.Text = if ($forever -or -not $Setting.rawValue) { '0' } else { "$($Setting.rawValue)" }
            $tb.IsEnabled = -not $forever
            $chk = New-Object System.Windows.Controls.CheckBox
            $chk.Content = $Ui.ForeverCheckboxLabel
            $chk.Margin = '0,8,0,0'
            $chk.IsChecked = $forever
            $chk.Add_Checked({ $tb.IsEnabled = $false })
            $chk.Add_Unchecked({ $tb.IsEnabled = $true })
            [void]$panel.Children.Add((New-LabeledControl -LabelText $Ui.LockoutDurationLabel -Control $tb))
            [void]$panel.Children.Add($chk)
            $control = $panel
            $control | Add-Member -NotePropertyName ForeverCheckBox -NotePropertyValue $chk
            $control | Add-Member -NotePropertyName MinutesTextBox -NotePropertyValue $tb
        }
        'principal-list' {
            $panel = New-Object System.Windows.Controls.StackPanel
            $listBox = New-Object System.Windows.Controls.ListBox
            $listBox.Height = 140
            $listBox.DisplayMemberPath = 'Display'
            foreach ($m in (ConvertTo-PrivilegeMemberList -Value $Setting.rawValue)) {
                [void]$listBox.Items.Add([pscustomobject]@{ Raw = $m; Display = (Resolve-PrincipalDisplayName -RawToken $m) })
            }
            $inputRow = New-Object System.Windows.Controls.StackPanel
            $inputRow.Orientation = 'Horizontal'
            $inputRow.Margin = '0,8,0,0'
            $addBtn = New-Object System.Windows.Controls.Button
            $addBtn.Content = $Ui.AddPrincipalButton
            $addBtn.Padding = '8,2'
            $removeBtn = New-Object System.Windows.Controls.Button
            $removeBtn.Content = $Ui.RemoveButton
            $removeBtn.Margin = '6,0,0,0'
            $removeBtn.Padding = '8,2'
            $addBtn.Add_Click({
                $picked = Show-SelectPrincipalsDialog -Owner $window -ScriptRoot $ScriptRoot -Ui $Ui
                foreach ($p in @($picked)) {
                    $already = @($listBox.Items | Where-Object { $_.Raw -eq $p.Raw })
                    if ($already.Count -eq 0) { [void]$listBox.Items.Add($p) }
                }
            })
            $removeBtn.Add_Click({
                if ($listBox.SelectedItem) { $listBox.Items.Remove($listBox.SelectedItem) }
            })
            [void]$inputRow.Children.Add($addBtn)
            [void]$inputRow.Children.Add($removeBtn)
            [void]$panel.Children.Add((New-LabeledControl -LabelText $Ui.PrincipalListLabel -Control $listBox))
            [void]$panel.Children.Add($inputRow)
            $control = $panel
            $control | Add-Member -NotePropertyName ListBoxControl -NotePropertyValue $listBox
        }
        'reg-boolean' {
            $control = New-Object System.Windows.Controls.ComboBox
            foreach ($opt in @($Ui.StateDisabled, $Ui.StateEnabled)) { [void]$control.Items.Add($opt) }
            $parsed = ConvertFrom-RegistryValuesEncoding -RawValue $Setting.rawValue
            $control.SelectedIndex = if ($parsed -and $parsed.Data -eq '1') { 1 } else { 0 }
        }
        'reg-number' {
            $control = New-Object System.Windows.Controls.TextBox
            $control.Width = 100
            $control.HorizontalAlignment = 'Left'
            $parsed = ConvertFrom-RegistryValuesEncoding -RawValue $Setting.rawValue
            $control.Text = if ($parsed) { $parsed.Data } else { '0' }
        }
        'reg-string' {
            $control = New-Object System.Windows.Controls.TextBox
            $parsed = ConvertFrom-RegistryValuesEncoding -RawValue $Setting.rawValue
            $control.Text = if ($parsed) { $parsed.Data } else { '' }
        }
        'reg-multistring' {
            # Same pattern as 'principal-list' (ListBox + Add/Remove), but
            # without accounts/groups wording - generic list.
            $panel = New-Object System.Windows.Controls.StackPanel
            $listBox = New-Object System.Windows.Controls.ListBox
            $listBox.Height = 120
            $parsed = ConvertFrom-RegistryValuesEncoding -RawValue $Setting.rawValue
            if ($parsed) {
                foreach ($m in @($parsed.Data -split ',' | Where-Object { $_ -ne '' })) { [void]$listBox.Items.Add($m) }
            }
            $inputRow = New-Object System.Windows.Controls.StackPanel
            $inputRow.Orientation = 'Horizontal'
            $inputRow.Margin = '0,8,0,0'
            $inputBox = New-Object System.Windows.Controls.TextBox
            $inputBox.Width = 260
            $addBtn = New-Object System.Windows.Controls.Button
            $addBtn.Content = $Ui.AddButton
            $addBtn.Margin = '6,0,0,0'
            $addBtn.Padding = '8,2'
            $removeBtn = New-Object System.Windows.Controls.Button
            $removeBtn.Content = $Ui.RemoveButton
            $removeBtn.Margin = '6,0,0,0'
            $removeBtn.Padding = '8,2'
            $addBtn.Add_Click({
                if ($inputBox.Text) { [void]$listBox.Items.Add($inputBox.Text); $inputBox.Text = '' }
            })
            $removeBtn.Add_Click({
                if ($listBox.SelectedItem) { $listBox.Items.Remove($listBox.SelectedItem) }
            })
            [void]$inputRow.Children.Add($inputBox)
            [void]$inputRow.Children.Add($addBtn)
            [void]$inputRow.Children.Add($removeBtn)
            [void]$panel.Children.Add((New-LabeledControl -LabelText $Ui.ElementListLabel -Control $listBox))
            [void]$panel.Children.Add($inputRow)
            $control = $panel
            $control | Add-Member -NotePropertyName ListBoxControl -NotePropertyValue $listBox
        }
        'reg-enum' {
            $control = New-Object System.Windows.Controls.ComboBox
            $choices = @($Setting.choices)
            foreach ($choice in $choices) { [void]$control.Items.Add($choice.displayName) }
            $parsed = ConvertFrom-RegistryValuesEncoding -RawValue $Setting.rawValue
            $selIdx = 0
            if ($parsed) {
                for ($i = 0; $i -lt $choices.Count; $i++) {
                    if ("$($choices[$i].value)" -eq $parsed.Data) { $selIdx = $i; break }
                }
            }
            $control.SelectedIndex = $selIdx
            $control | Add-Member -NotePropertyName ChoiceValues -NotePropertyValue @($choices | ForEach-Object { $_.value })
        }
        'reg-flags' {
            # Bitmask shown as independent checkboxes (one per bit), same
            # as the real console does for NTLMMinClientSec/ServerSec - see
            # Format-SecuritySettingValue (PolicyState.ps1) for the "State"
            # list display.
            $panel = New-Object System.Windows.Controls.StackPanel
            $parsed = ConvertFrom-RegistryValuesEncoding -RawValue $Setting.rawValue
            $current = 0
            if ($parsed) { [void][int]::TryParse($parsed.Data, [ref]$current) }
            $checkBoxes = New-Object System.Collections.Generic.List[object]
            foreach ($flag in @($Setting.flags)) {
                $chk = New-Object System.Windows.Controls.CheckBox
                $chk.Content = $flag.displayName
                $chk.Margin = '0,0,0,6'
                $chk.IsChecked = (($current -band $flag.value) -ne 0)
                $chk | Add-Member -NotePropertyName FlagValue -NotePropertyValue $flag.value
                [void]$panel.Children.Add($chk)
                $checkBoxes.Add($chk)
            }
            $control = $panel
            $control | Add-Member -NotePropertyName FlagCheckBoxes -NotePropertyValue $checkBoxes
        }
        default {
            $control = New-Object System.Windows.Controls.TextBox
            $control.Text = "$($Setting.rawValue)"
        }
    }

    [void]$valueEditorPanel.Children.Add($control)

    $updateEnabled = { $valueEditorPanel.IsEnabled = ($isConfiguredCheck.IsChecked -eq $true) }
    $isConfiguredCheck.Add_Checked($updateEnabled)
    $isConfiguredCheck.Add_Unchecked($updateEnabled)
    & $updateEnabled

    $script:__secDialogResult = $null

    $okButton.Add_Click({
        $isConfigured = ($isConfiguredCheck.IsChecked -eq $true)
        $value = $null

        if ($isConfigured) {
            switch ($Setting.valueType) {
                'boolean' { $value = if ($control.SelectedIndex -eq 1) { '1' } else { '0' } }
                'audit'   { $value = "$($control.SelectedIndex)" }
                'minutes-or-forever' {
                    if ($control.ForeverCheckBox.IsChecked) { $value = '-1' }
                    else {
                        $n = 0
                        if (-not [int]::TryParse($control.MinutesTextBox.Text, [ref]$n)) {
                            [System.Windows.MessageBox]::Show($Ui.InvalidNumberMessageGeneric, $Ui.ErrorTitle, 'OK', 'Warning') | Out-Null
                            return
                        }
                        $value = "$n"
                    }
                }
                'principal-list' {
                    $members = @($control.ListBoxControl.Items | ForEach-Object { $_.Raw })
                    $value = ConvertFrom-PrivilegeMemberList -Members $members
                }
                'reg-boolean' {
                    $regType = if ($Setting.regType) { $Setting.regType } else { 4 }
                    $value = if ($control.SelectedIndex -eq 1) { ConvertTo-RegistryValuesEncoding -RegType $regType -Data '1' } else { ConvertTo-RegistryValuesEncoding -RegType $regType -Data '0' }
                }
                'reg-number' {
                    $n = 0
                    if (-not [int]::TryParse($control.Text, [ref]$n)) {
                        [System.Windows.MessageBox]::Show($Ui.InvalidNumberMessageGeneric, $Ui.ErrorTitle, 'OK', 'Warning') | Out-Null
                        return
                    }
                    $value = ConvertTo-RegistryValuesEncoding -RegType $(if ($Setting.regType) { $Setting.regType } else { 4 }) -Data "$n"
                }
                'reg-string' { $value = ConvertTo-RegistryValuesEncoding -RegType $(if ($Setting.regType) { $Setting.regType } else { 1 }) -Data $control.Text }
                'reg-multistring' {
                    $items = @($control.ListBoxControl.Items | ForEach-Object { $_ })
                    $value = ConvertTo-RegistryValuesEncoding -RegType 7 -Data ($items -join ',')
                }
                'reg-enum' { $value = ConvertTo-RegistryValuesEncoding -RegType 4 -Data "$($control.ChoiceValues[$control.SelectedIndex])" }
                'reg-flags' {
                    $sum = 0
                    foreach ($chk in $control.FlagCheckBoxes) { if ($chk.IsChecked -eq $true) { $sum = $sum -bor $chk.FlagValue } }
                    $value = ConvertTo-RegistryValuesEncoding -RegType 4 -Data "$sum"
                }
                default { $value = $control.Text }
            }
        }

        $script:__secDialogResult = @{ IsConfigured = $isConfigured; Value = $value }
        $window.DialogResult = $true
        $window.Close()
    })

    $cancelButton.Add_Click({
        $window.DialogResult = $false
        $window.Close()
    })

    $null = $window.ShowDialog()
    return $script:__secDialogResult
}
