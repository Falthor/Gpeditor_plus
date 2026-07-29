<#
    Read/write GPT.ini: [General] / Version=<DWORD>. Version packs two
    independent 16-bit counters (high word = "Machine", low word = "User").
    Windows compares these on every gpupdate to decide whether
    Computer/User settings need reprocessing - must be incremented on every
    registry.pol/GptTmpl.inf write to take effect.
#>

Set-StrictMode -Off

function Read-GptIni {
    param([Parameter(Mandatory)][string]$Path)

    $sections = [ordered]@{}
    $sections['General'] = [ordered]@{ Version = '0' }

    if (Test-Path -LiteralPath $Path) {
        $text = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::Default)
        $currentSection = $null

        foreach ($rawLine in ($text -split "`r`n|`n")) {
            $line = $rawLine.Trim()
            if ($line.Length -eq 0) { continue }

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
    }

    if (-not $sections['General'].Contains('Version')) { $sections['General']['Version'] = '0' }

    return [ordered]@{ Sections = $sections }
}

function Write-GptIni {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$GptIni)

    $sb = New-Object System.Text.StringBuilder
    foreach ($secName in $GptIni.Sections.Keys) {
        [void]$sb.Append("[$secName]`r`n")
        foreach ($key in $GptIni.Sections[$secName].Keys) {
            [void]$sb.Append("$key=$($GptIni.Sections[$secName][$key])`r`n")
        }
    }

    $outDir = Split-Path -Parent $Path
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), [System.Text.Encoding]::Default)
}

function Step-GptIniVersion {
    # Increments the Machine and/or User counter of the Version DWORD.
    param([Parameter(Mandatory)]$GptIni, [switch]$IncrementMachine, [switch]$IncrementUser)

    $raw = $GptIni.Sections['General']['Version']
    $current = 0
    [uint32]::TryParse($raw, [ref]$current) | Out-Null

    $machineVersion = ($current -shr 16) -band 0xFFFF
    $userVersion = $current -band 0xFFFF

    if ($IncrementMachine) { $machineVersion = ($machineVersion + 1) -band 0xFFFF }
    if ($IncrementUser) { $userVersion = ($userVersion + 1) -band 0xFFFF }

    $newVersion = ([uint32]$machineVersion -shl 16) -bor [uint32]$userVersion
    $GptIni.Sections['General']['Version'] = "$newVersion"
    return $GptIni
}
