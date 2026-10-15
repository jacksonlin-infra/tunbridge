[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Executables
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$dumpbin = Get-Command dumpbin.exe -ErrorAction SilentlyContinue
if ($null -eq $dumpbin) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        throw 'Visual Studio vswhere.exe is required to check Windows CRT dependencies'
    }
    $candidates = @(& $vswhere -latest -products '*' -find 'VC\Tools\MSVC\**\bin\Hostx64\x64\dumpbin.exe')
    if ($LASTEXITCODE -ne 0 -or $candidates.Count -eq 0) {
        throw 'MSVC dumpbin.exe is required to check Windows CRT dependencies'
    }
    $dumpbinPath = $candidates[0]
} else {
    $dumpbinPath = $dumpbin.Source
}

foreach ($executable in $Executables) {
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "Windows executable is missing: $executable"
    }
    $dependencies = & $dumpbinPath /dependents $executable
    if ($LASTEXITCODE -ne 0) {
        throw "dumpbin failed for $executable"
    }
    if ($dependencies -match '(?i)\b(?:VCRUNTIME|MSVCP|CONCRT)\d+(?:_\d+)?\.dll\b') {
        throw "Windows executable requires a separately installed Visual C++ runtime: $executable"
    }
    Write-Output "windows_crt_dependencies=ok file=$([IO.Path]::GetFileName($executable))"
}
