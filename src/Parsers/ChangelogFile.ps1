<#
    Reads CHANGELOG.md (project root): feeds the right-hand "Release notes"
    panel (before any selection/search, see plan-gpedit-ui-enhancements.md
    §2) and the ? > Patch note window (§3.d).

    Expected format ("Keep a Changelog" style):

        ## 2026-07-23 - Entry title
        - Change line
        - Another change line

        ## 2026-07-10 - Previous entry
        - ...

    Entries are returned in file order (most recent first, provided the
    file is kept that way).
#>

Set-StrictMode -Version Latest

function Get-ChangelogEntry {
    param([string]$Path)

    $entries = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $Path)) { return $entries }

    $lines = Get-Content -LiteralPath $Path -Encoding UTF8
    $current = $null
    foreach ($line in $lines) {
        if ($line -match '^##\s+(?<date>\d{4}-\d{2}-\d{2})\s*[—-]\s*(?<title>.+)$') {
            if ($current) { $entries.Add($current) }
            $current = [pscustomobject]@{
                Date  = $Matches['date']
                Title = $Matches['title'].Trim()
                Items = New-Object System.Collections.Generic.List[string]
            }
            continue
        }
        if ($null -eq $current) { continue }
        if ($line -match '^\s*-\s+(?<item>.+)$') {
            $current.Items.Add($Matches['item'].Trim())
            continue
        }
        # Continuation line of an item wrapped across multiple source lines:
        # append to the last item instead of dropping it.
        if ($current.Items.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($line)) {
            $lastIndex = $current.Items.Count - 1
            $current.Items[$lastIndex] = "$($current.Items[$lastIndex]) $($line.Trim())"
        }
    }
    if ($current) { $entries.Add($current) }
    return $entries
}

function Set-ChangelogTextBlockContent {
    <#
        Fills $TextBlock.Inlines with changelog entries (bold date) instead
        of a plain Text assignment - only way to bold the date in a WPF
        TextBlock without a FlowDocument. $MaxEntries = 0 means "all entries".
    #>
        [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]$TextBlock,
        [Parameter(Mandatory)][System.Collections.Generic.List[object]]$Entries,
        [int]$MaxEntries = 0,
        [string]$EmptyText = ''
    )
    if ($PSCmdlet.ShouldProcess('Set-ChangelogTextBlockContent', 'Invoke')) {

    $TextBlock.Inlines.Clear()
    if ($Entries.Count -eq 0) {
        if ($EmptyText) { [void]$TextBlock.Inlines.Add((New-Object System.Windows.Documents.Run($EmptyText))) }
        return
    }

    $shown = if ($MaxEntries -gt 0) { $Entries | Select-Object -First $MaxEntries } else { $Entries }
    $isFirst = $true
    foreach ($entry in $shown) {
        if (-not $isFirst) {
            [void]$TextBlock.Inlines.Add((New-Object System.Windows.Documents.LineBreak))
            [void]$TextBlock.Inlines.Add((New-Object System.Windows.Documents.LineBreak))
        }
        $isFirst = $false

        $header = New-Object System.Windows.Documents.Bold
        [void]$header.Inlines.Add((New-Object System.Windows.Documents.Run("$($entry.Date) — $($entry.Title)")))
        [void]$TextBlock.Inlines.Add($header)

        foreach ($item in $entry.Items) {
            [void]$TextBlock.Inlines.Add((New-Object System.Windows.Documents.LineBreak))
            [void]$TextBlock.Inlines.Add((New-Object System.Windows.Documents.Run("- $item")))
        }
    }

    }
}
