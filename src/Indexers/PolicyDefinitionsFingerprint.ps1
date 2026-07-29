<#
    SHA256 fingerprint of the PolicyDefinitions folder (relative path + size
    + last-write time per .admx/.adml file). Lets us detect that the cached
    admx-index.json is stale without re-reading all 215+ files.
#>

Set-StrictMode -Version Latest

function Get-PolicyDefinitionsFingerprint {
    param(
        [Parameter(Mandatory)][string]$PolicyDefinitionsPath,
        [Parameter(Mandatory)][string]$Language
    )

    if (-not (Test-Path -LiteralPath $PolicyDefinitionsPath)) { return 'absent' }

    $admxFiles = Get-ChildItem -LiteralPath $PolicyDefinitionsPath -Filter '*.admx' -File -ErrorAction SilentlyContinue
    $langPath = Join-Path $PolicyDefinitionsPath $Language
    $admlFiles = if (Test-Path -LiteralPath $langPath) {
        Get-ChildItem -LiteralPath $langPath -Filter '*.adml' -File -ErrorAction SilentlyContinue
    } else { @() }

    $files = @($admxFiles) + @($admlFiles) | Sort-Object FullName

    $sb = New-Object System.Text.StringBuilder
    $rootLength = $PolicyDefinitionsPath.TrimEnd('\').Length
    foreach ($f in $files) {
        [void]$sb.Append($f.FullName.Substring($rootLength))
        [void]$sb.Append('|')
        [void]$sb.Append($f.Length)
        [void]$sb.Append('|')
        [void]$sb.Append($f.LastWriteTimeUtc.Ticks)
        [void]$sb.Append("`n")
    }

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($sb.ToString())
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha256.ComputeHash($bytes)
        return [Convert]::ToBase64String($hashBytes)
    }
    finally {
        $sha256.Dispose()
    }
}

