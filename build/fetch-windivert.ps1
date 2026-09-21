#Requires -Version 5.1
<#
.SYNOPSIS
    Descarga WinDivert 2.2.2 oficial y copia WinDivert.dll y WinDivert64.sys
    junto al ejecutable publicado.
#>
param(
    [Parameter(Mandatory = $true)]
    [string] $OutputDirectory
)

$ErrorActionPreference = 'Stop'

$Version = '2.2.2'
$Url = "https://github.com/basil00/WinDivert/releases/download/v$Version/WinDivert-$Version-A.zip"
$ExpectedHash = '63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15'

$destination = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $destination | Out-Null

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("proxyapp-windivert-" + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null

try {
    $zipPath = Join-Path $tempRoot "WinDivert-$Version-A.zip"
    Invoke-WebRequest -Uri $Url -OutFile $zipPath -UseBasicParsing

    $actual = (Get-FileHash -Algorithm SHA256 -Path $zipPath).Hash
    if ($actual -ne $ExpectedHash) {
        throw "El ZIP de WinDivert no coincide con el hash fijado. Esperado $ExpectedHash, recibido $actual."
    }

    $extract = Join-Path $tempRoot 'extract'
    Expand-Archive -Path $zipPath -DestinationPath $extract -Force

    $dll = Join-Path $extract "WinDivert-$Version-A\x64\WinDivert.dll"
    $sys = Join-Path $extract "WinDivert-$Version-A\x64\WinDivert64.sys"
    if (-not (Test-Path $dll) -or -not (Test-Path $sys)) {
        throw 'El ZIP oficial no contiene x64\WinDivert.dll y x64\WinDivert64.sys.'
    }

    Copy-Item -Path $dll -Destination (Join-Path $destination 'WinDivert.dll') -Force
    Copy-Item -Path $sys -Destination (Join-Path $destination 'WinDivert64.sys') -Force
}
finally {
    if (Test-Path $tempRoot) {
        Remove-Item -Recurse -Force $tempRoot
    }
}
