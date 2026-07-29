<#
    Read/write GptTmpl.inf: local security settings (passwords, lockout,
    user rights, audit policy). Usually UTF-16LE with BOM ([Unicode] /
    Unicode=yes), but Windows reads it tolerantly - what matters is DATA
    fidelity (no section/key lost), not exact bytes.
#>

Set-StrictMode -Version Latest

function Get-GptTmplEncoding {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return 'Unicode' }

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { return 'Unicode' }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) { return 'BigEndianUnicode' }
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { return 'UTF8' }
    return 'Default'
}

function Get-GptTmplTextEncoding {
    param([string]$EncodingName)
    switch ($EncodingName) {
        'Unicode'          { return New-Object System.Text.UnicodeEncoding($false, $true) }
        'BigEndianUnicode' { return New-Object System.Text.UnicodeEncoding($true, $true) }
        'UTF8'             { return New-Object System.Text.UTF8Encoding($true) }
        default            { return [System.Text.Encoding]::Default }
    }
}

function New-EmptyGptTmpl {
    $gpt = [ordered]@{
        Encoding = 'Unicode'
        Sections = [ordered]@{}
    }
    $gpt.Sections['Unicode'] = [ordered]@{ Unicode = 'yes' }
    $gpt.Sections['Version'] = [ordered]@{ signature = '"$CHICAGO$"'; Revision = '1' }
    return $gpt
}

function Read-GptTmplInf {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return New-EmptyGptTmpl
    }

    $encodingName = Get-GptTmplEncoding -Path $Path
    $encoding = Get-GptTmplTextEncoding -EncodingName $encodingName
    $text = [System.IO.File]::ReadAllText($Path, $encoding)

    $sections = [ordered]@{}
    $currentSection = $null

    foreach ($rawLine in ($text -split "`r`n|`n")) {
        $line = $rawLine.Trim()
        if ($line.Length -eq 0) { continue }
        if ($line.StartsWith(';')) { continue }

        if ($line -match '^\[(.+)\]$') {
            $currentSection = $Matches[1]
            if (-not $sections.Contains($currentSection)) { $sections[$currentSection] = [ordered]@{} }
            continue
        }

        if ($null -eq $currentSection) { continue }
        $idx = $line.IndexOf('=')
        if ($idx -lt 0) { continue }

        $key = $line.Substring(0, $idx).Trim()
        $value = $line.Substring($idx + 1).Trim()
        $sections[$currentSection][$key] = $value
    }

    return [ordered]@{
        Encoding = $encodingName
        Sections = $sections
    }
}

function Write-GptTmplInf {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$GptTmpl
    )
    $encoding = Get-GptTmplTextEncoding -EncodingName $GptTmpl.Encoding

    $sb = New-Object System.Text.StringBuilder
    foreach ($secName in $GptTmpl.Sections.Keys) {
        [void]$sb.Append("[$secName]`r`n")
        foreach ($key in $GptTmpl.Sections[$secName].Keys) {
            [void]$sb.Append("$key = $($GptTmpl.Sections[$secName][$key])`r`n")
        }
    }

    $outDir = Split-Path -Parent $Path
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), $encoding)
}

function Get-GptTmplValue {
    param($GptTmpl, [string]$Section, [string]$Key)
    if ($GptTmpl.Sections.Contains($Section) -and $GptTmpl.Sections[$Section].Contains($Key)) {
        return $GptTmpl.Sections[$Section][$Key]
    }
    return $null
}

function Set-GptTmplValue {
    param($GptTmpl, [string]$Section, [string]$Key, [string]$Value)
    if (-not $GptTmpl.Sections.Contains($Section)) {
        $GptTmpl.Sections[$Section] = [ordered]@{}
    }
    $GptTmpl.Sections[$Section][$Key] = $Value
}

function Remove-GptTmplValue {
    param($GptTmpl, [string]$Section, [string]$Key)
    if ($GptTmpl.Sections.Contains($Section) -and $GptTmpl.Sections[$Section].Contains($Key)) {
        $GptTmpl.Sections[$Section].Remove($Key)
    }
}

function ConvertTo-PrivilegeMemberList {
    # "*S-1-5-32-544,*S-1-5-32-545" -> @('*S-1-5-32-544','*S-1-5-32-545')
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return , @() }
    return , @(($Value -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
}

function ConvertFrom-PrivilegeMemberList {
    param([string[]]$Members)
    return ((@($Members) | Where-Object { $_ }) -join ',')
}
