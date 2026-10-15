[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$scratchRoot = Join-Path ([IO.Path]::GetTempPath()) "tunbridge-setup-smoke-$PID"
$packageDirectory = Join-Path $scratchRoot 'package'
$outputDirectory = Join-Path $scratchRoot 'output'
$requiredFiles = @(
    'tunbridge-desktop.exe',
    'tunbridge-setup.exe',
    'tunbridge-service.exe',
    'tunbridge.exe',
    'mihomo.exe',
    'engines.lock.json',
    'product-package.json'
)

try {
    New-Item -ItemType Directory -Path $packageDirectory -Force | Out-Null
    foreach ($file in $requiredFiles) {
        [IO.File]::WriteAllBytes((Join-Path $packageDirectory $file), [byte[]](0x54, 0x42))
    }
    $builder = Join-Path $repositoryRoot 'platforms\windows\packaging\build-windows-setup.ps1'
    & $builder -PackageDirectory $packageDirectory -OutputDirectory $outputDirectory -ProductVersion '0.0.0'
    $installer = Join-Path $outputDirectory 'TunBridge-0.0.0-windows-x86_64-setup.exe'
    if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
        throw 'NSIS smoke build did not produce the expected Setup executable'
    }
    Write-Output 'windows_setup_compile=ok'
}
finally {
    if (Test-Path -LiteralPath $scratchRoot) {
        Remove-Item -LiteralPath $scratchRoot -Recurse -Force
    }
}
