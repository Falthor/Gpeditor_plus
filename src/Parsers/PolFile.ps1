<#
    Step 2 - Custom parser for the registry.pol binary format (PReg)

    Format (publicly documented by Microsoft):
      Header: DWORD signature = 0x67655250 ("PReg" ASCII, read LE)
              DWORD version   = 1
      Then a sequence of entries, each:
        '[' KeyName(null-terminated wstr) ';' ValueName(null-terminated wstr) ';'
            Type(DWORD) ';' Size(DWORD) ';' Data(Size bytes) ']'
      All separator chars ('[',';',']') are UTF-16LE (2 bytes), like the
      rest of the file.
#>

Set-StrictMode -Version Latest

$script:PReg_Signature = 0x67655250
$script:PReg_Version   = 1

function Get-RegTypeName {
    param([int]$Type)
    switch ($Type) {
        0  { 'REG_NONE' }
        1  { 'REG_SZ' }
        2  { 'REG_EXPAND_SZ' }
        3  { 'REG_BINARY' }
        4  { 'REG_DWORD' }
        5  { 'REG_DWORD_BIG_ENDIAN' }
        6  { 'REG_LINK' }
        7  { 'REG_MULTI_SZ' }
        11 { 'REG_QWORD' }
        default { "REG_UNKNOWN_$Type" }
    }
}

function Get-RegTypeValue {
    param([string]$TypeName)
    switch ($TypeName) {
        'REG_NONE'             { 0 }
        'REG_SZ'               { 1 }
        'REG_EXPAND_SZ'        { 2 }
        'REG_BINARY'           { 3 }
        'REG_DWORD'            { 4 }
        'REG_DWORD_BIG_ENDIAN' { 5 }
        'REG_LINK'             { 6 }
        'REG_MULTI_SZ'         { 7 }
        'REG_QWORD'            { 11 }
        default { throw "Unknown registry type: $TypeName" }
    }
}

function Get-WideStringTrimNull {
    param([byte[]]$Data)
    if ($null -eq $Data -or $Data.Length -eq 0) { return '' }
    $s = [System.Text.Encoding]::Unicode.GetString($Data)
    return $s.TrimEnd([char]0)
}

function ConvertFrom-PolData {
    # See note in ConvertTo-PolData: REG_BINARY must return an unrolled-free
    # Byte[] (comma operator) to stay usable as-is by ConvertTo-PolData on rewrite.
    param([int]$Type, [byte[]]$Data)

    switch ($Type) {
        { $_ -in 1, 2, 6 } { return (Get-WideStringTrimNull $Data) }
        7 {
            $s = [System.Text.Encoding]::Unicode.GetString($Data)
            $parts = $s -split "`0"
            return , @($parts | Where-Object { $_ -ne '' })
        }
        4 {
            if ($Data.Length -ge 4) { return [BitConverter]::ToUInt32($Data, 0) }
            return 0
        }
        5 {
            if ($Data.Length -ge 4) {
                $rev = @($Data[3], $Data[2], $Data[1], $Data[0])
                return [BitConverter]::ToUInt32($rev, 0)
            }
            return 0
        }
        11 {
            if ($Data.Length -ge 8) { return [BitConverter]::ToUInt64($Data, 0) }
            return 0
        }
        default { return , $Data }
    }
}

function ConvertTo-PolData {
    # IMPORTANT: any System.Byte[] returned from a PowerShell function is
    # unrolled element-by-element onto the output stream and reassembled as
    # System.Object[] by the caller. The unary comma operator ",$x" prevents
    # that and preserves the Byte[] type (needed here: BinaryWriter.Write()
    # picks a different, invalid overload for Object[]).
    param([int]$Type, $Value)

    [byte[]]$bytes = switch ($Type) {
        { $_ -in 1, 2, 6 } {
            $s = if ($null -eq $Value) { '' } else { [string]$Value }
            [System.Text.Encoding]::Unicode.GetBytes($s + [char]0)
        }
        7 {
            $sb = New-Object System.Text.StringBuilder
            foreach ($item in @($Value)) {
                [void]$sb.Append([string]$item)
                [void]$sb.Append([char]0)
            }
            [void]$sb.Append([char]0)
            [System.Text.Encoding]::Unicode.GetBytes($sb.ToString())
        }
        4 { [BitConverter]::GetBytes([uint32]$Value) }
        5 {
            $b = [BitConverter]::GetBytes([uint32]$Value)
            [byte[]]@($b[3], $b[2], $b[1], $b[0])
        }
        11 { [BitConverter]::GetBytes([uint64]$Value) }
        default {
            if ($Value -is [byte[]]) { $Value } else { New-Object byte[] 0 }
        }
    }
    return , $bytes
}

function New-PolEntry {
    param(
        [Parameter(Mandatory)][string]$KeyName,
        [Parameter(Mandatory)][string]$ValueName,
        [Parameter(Mandatory)][int]$Type,
        $Value
    )
    $data = ConvertTo-PolData -Type $Type -Value $Value
    return [ordered]@{
        KeyName   = $KeyName
        ValueName = $ValueName
        Type      = $Type
        TypeName  = Get-RegTypeName $Type
        Size      = $data.Length
        RawData   = $data
        Value     = $Value
    }
}

function Read-PolFile {
    param([Parameter(Mandatory)][string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 8) {
        throw "Invalid .pol file (too small, $($bytes.Length) bytes): $Path"
    }

    $ms = New-Object System.IO.MemoryStream(, $bytes)
    $br = New-Object System.IO.BinaryReader($ms)
    try {
        $signature = $br.ReadUInt32()
        if ($signature -ne $script:PReg_Signature) {
            throw "Invalid PReg signature in $Path (0x$($signature.ToString('X8')))"
        }
        $version = $br.ReadUInt32()
        if ($version -ne $script:PReg_Version) {
            Write-Warning "Unexpected registry.pol version ($version) in $Path"
        }

        $entries = New-Object System.Collections.Generic.List[object]

        while ($ms.Position -lt $ms.Length) {
            $c = [char]$br.ReadUInt16()
            if ($c -ne '[') { throw "Invalid .pol format: '[' expected at position $($ms.Position - 2), got '$c'" }

            $keyName = Read-PolWideString -BinaryReader $br

            $c = [char]$br.ReadUInt16()
            if ($c -ne ';') { throw "Invalid .pol format: ';' expected after KeyName at position $($ms.Position - 2)" }

            $valueName = Read-PolWideString -BinaryReader $br

            $c = [char]$br.ReadUInt16()
            if ($c -ne ';') { throw "Invalid .pol format: ';' expected after ValueName at position $($ms.Position - 2)" }

            $type = $br.ReadUInt32()

            $c = [char]$br.ReadUInt16()
            if ($c -ne ';') { throw "Invalid .pol format: ';' expected after Type at position $($ms.Position - 2)" }

            $size = $br.ReadUInt32()

            $c = [char]$br.ReadUInt16()
            if ($c -ne ';') { throw "Invalid .pol format: ';' expected after Size at position $($ms.Position - 2)" }

            # Explicitly typed as Byte[]: forces reconversion even though
            # the if/else expression unrolls the array in the process.
            [byte[]]$data = if ($size -gt 0) { $br.ReadBytes($size) } else { New-Object byte[] 0 }
            if ($data.Length -ne $size) { throw "Truncated .pol file: missing data for $keyName\$valueName" }

            $c = [char]$br.ReadUInt16()
            if ($c -ne ']') { throw "Invalid .pol format: ']' expected at end of entry for $keyName\$valueName" }

            $entries.Add([ordered]@{
                KeyName   = $keyName
                ValueName = $valueName
                Type      = $type
                TypeName  = Get-RegTypeName $type
                Size      = $size
                RawData   = $data
                Value     = ConvertFrom-PolData -Type $type -Data $data
            })
        }

        return , $entries
    }
    finally {
        $br.Close()
        $ms.Close()
    }
}

function Read-PolWideString {
    param($BinaryReader)
    $sb = New-Object System.Text.StringBuilder
    while ($true) {
        $u = $BinaryReader.ReadUInt16()
        if ($u -eq 0) { break }
        [void]$sb.Append([char]$u)
    }
    return $sb.ToString()
}

function Write-PolFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][System.Collections.IEnumerable]$Entries
    )

    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter($ms)
    try {
        $bw.Write([uint32]$script:PReg_Signature)
        $bw.Write([uint32]$script:PReg_Version)

        foreach ($e in $Entries) {
            Write-PolChar -BinaryWriter $bw -Char '['
            Write-PolWideString -BinaryWriter $bw -Value $e.KeyName
            Write-PolChar -BinaryWriter $bw -Char ';'
            Write-PolWideString -BinaryWriter $bw -Value $e.ValueName
            Write-PolChar -BinaryWriter $bw -Char ';'
            $bw.Write([uint32]$e.Type)
            Write-PolChar -BinaryWriter $bw -Char ';'

            $data = $null
            if ($e -is [System.Collections.IDictionary] -and $e.Contains('RawData') -and $null -ne $e['RawData']) {
                $data = $e['RawData']
            }
            else {
                $data = ConvertTo-PolData -Type $e.Type -Value $e.Value
            }

            $bw.Write([uint32]$data.Length)
            Write-PolChar -BinaryWriter $bw -Char ';'
            if ($data.Length -gt 0) { $bw.Write($data) }
            Write-PolChar -BinaryWriter $bw -Char ']'
        }

        $bw.Flush()
        [System.IO.File]::WriteAllBytes($Path, $ms.ToArray())
    }
    finally {
        $bw.Close()
        $ms.Close()
    }
}

function Write-PolChar {
    param($BinaryWriter, [char]$Char)
    $BinaryWriter.Write([uint16][int]$Char)
}

function Write-PolWideString {
    param($BinaryWriter, [string]$Value)
    if ($null -eq $Value) { $Value = '' }
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($Value)
    $BinaryWriter.Write($bytes)
    $BinaryWriter.Write([uint16]0)
}

# --- Special .pol format markers for value deletion ---
# Used on write (Step 6) to set a policy back to "Not Configured": the real
# value is removed from the registry on next gpupdate via a marker entry
# rather than by deleting from the file.
$script:PolDeleteValuePrefix    = '**del.'
$script:PolDeleteAllValuesName  = '**delvals.'

function New-PolDeleteValueEntry {
    param([Parameter(Mandatory)][string]$KeyName, [Parameter(Mandatory)][string]$ValueName)
    return New-PolEntry -KeyName $KeyName -ValueName ($script:PolDeleteValuePrefix + $ValueName) -Type 1 -Value ''
}

function New-PolDeleteAllValuesEntry {
    param([Parameter(Mandatory)][string]$KeyName)
    return New-PolEntry -KeyName $KeyName -ValueName $script:PolDeleteAllValuesName -Type 1 -Value ''
}

function Test-PolValueIsDeleteMarker {
    param([string]$ValueName)
    return $ValueName.StartsWith($script:PolDeleteValuePrefix) -or $ValueName -eq $script:PolDeleteAllValuesName
}
