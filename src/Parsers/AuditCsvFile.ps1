<#
    Read/write for the Advanced Audit Policy Configuration file:
    C:\Windows\System32\GroupPolicy\Machine\Microsoft\Windows NT\Audit\audit.csv

    Standard CSV columns (Microsoft-documented):
      Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value
    Subcategory GUID is the stable matching key (the "Subcategory" name is
    informational only); the file always gets the canonical English name
    regardless of UI language, translation happens only on display (see
    AdvancedAuditCatalog.ps1).

    Setting Value: 0 = No Auditing, 1 = Success, 2 = Failure, 3 = Success
    and Failure. "Inclusion Setting" mirrors it as text, matching what a
    real `auditpol /backup` produces.
#>

Set-StrictMode -Off

$script:AuditCsvHeader = 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'

function Get-AuditInclusionSettingText {
    param([int]$Value)
    switch ($Value) {
        0 { return 'No Auditing' }
        1 { return 'Success' }
        2 { return 'Failure' }
        3 { return 'Success and Failure' }
        default { return 'No Auditing' }
    }
}

function Read-AuditCsv {
    # Returns hashtable GUID (uppercase) -> row (column hashtable), keeping
    # columns/values as-is so no data is lost on a partial rewrite.
    param([Parameter(Mandatory)][string]$Path)

    $rows = @{}
    if (-not (Test-Path -LiteralPath $Path)) { return $rows }

    $lines = Get-Content -LiteralPath $Path -Encoding UTF8
    if ($lines.Count -le 1) { return $rows }

    $columns = ($lines[0] -split ',')
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $fields = $line -split ','
        $row = [ordered]@{}
        for ($c = 0; $c -lt $columns.Count -and $c -lt $fields.Count; $c++) {
            $row[$columns[$c].Trim()] = $fields[$c].Trim()
        }
        $guid = "$($row['Subcategory GUID'])".ToUpperInvariant()
        if ($guid) { $rows[$guid] = $row }
    }
    return $rows
}

function Write-AuditCsv {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][hashtable]$Rows
    )

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append($script:AuditCsvHeader)
    [void]$sb.Append("`r`n")
    foreach ($guid in ($Rows.Keys | Sort-Object)) {
        $row = $Rows[$guid]
        [void]$sb.Append("$($row['Machine Name']),$($row['Policy Target']),$($row['Subcategory']),$($row['Subcategory GUID']),$($row['Inclusion Setting']),$($row['Exclusion Setting']),$($row['Setting Value'])")
        [void]$sb.Append("`r`n")
    }

    $outDir = Split-Path -Parent $Path
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
}

function Set-AuditCsvValue {
    param(
        [Parameter(Mandatory)][hashtable]$Rows,
        [Parameter(Mandatory)][string]$Guid,
        [Parameter(Mandatory)][string]$SubcategoryName,
        [Parameter(Mandatory)][int]$SettingValue
    )
    $key = $Guid.ToUpperInvariant()
    $Rows[$key] = [ordered]@{
        'Machine Name'      = ''
        'Policy Target'     = 'System'
        'Subcategory'       = $SubcategoryName
        'Subcategory GUID'  = $Guid
        'Inclusion Setting' = Get-AuditInclusionSettingText -Value $SettingValue
        'Exclusion Setting' = ''
        'Setting Value'     = "$SettingValue"
    }
}

function Remove-AuditCsvValue {
    param([Parameter(Mandatory)][hashtable]$Rows, [Parameter(Mandatory)][string]$Guid)
    $key = $Guid.ToUpperInvariant()
    if ($Rows.ContainsKey($key)) { $Rows.Remove($key) }
}

function Get-AuditCsvValue {
    param([Parameter(Mandatory)][hashtable]$Rows, [Parameter(Mandatory)][string]$Guid)
    $key = $Guid.ToUpperInvariant()
    if ($Rows.ContainsKey($key)) { return $Rows[$key] }
    return $null
}
