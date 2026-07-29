<#
    SHA256 fingerprint of the Audit files folder (relative path + size +
    last-write time per *.audit file). Same idea as
    PolicyDefinitionsFingerprint.ps1: lets us detect that cis-index.json is
    stale (file added/removed/replaced, including outside the Options
    window) without reparsing every .audit file.
#>

Set-StrictMode -Version Latest

function Get-AuditFilesFingerprint {
    param(
        [Parameter(Mandatory)][string]$AuditFilesPath
    )

    if (-not (Test-Path -LiteralPath $AuditFilesPath)) { return 'absent' }

    $files = Get-ChildItem -LiteralPath $AuditFilesPath -Filter '*.audit' -File -ErrorAction SilentlyContinue | Sort-Object FullName

    $sb = New-Object System.Text.StringBuilder
    $rootLength = $AuditFilesPath.TrimEnd('\').Length
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
