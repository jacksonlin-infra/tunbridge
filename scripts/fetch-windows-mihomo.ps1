[CmdletBinding()]
param()

# Download the pinned Mihomo release for Windows x86_64 and verify both the
# archive and the extracted executable before the build may package it.
$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$version = 'v1.19.30'
$asset = 'mihomo-windows-amd64-v2-v1.19.30.zip'
$expectedArchiveSize = [uint64]18515120
$expectedArchiveSha256 = '837bcaa45aed61d698bba76da70c44818b1d345d497937b4db0fa5075e3c4a5c'
$url = "https://github.com/MetaCubeX/mihomo/releases/download/$version/$asset"
$downloadRoot = Join-Path $repositoryRoot 'target\windows-engine'
$archive = Join-Path $downloadRoot $asset
$binary = Join-Path $downloadRoot 'mihomo.exe'

$lock = Get-Content -LiteralPath (Join-Path $repositoryRoot 'engines.lock.json') -Raw | ConvertFrom-Json
if ($lock.schema_version -ne 1 -or $lock.engine.filename -ne 'mihomo.exe' -or
    $lock.engine.version -cne $version -or $lock.engine.asset -cne $asset) {
    throw 'engines.lock.json does not describe the engine this script downloads'
}
$expectedBinarySize = [uint64]$lock.engine.size
$expectedBinarySha256 = [string]$lock.engine.sha256

function Test-PinnedFile([string]$Path, [uint64]$Size, [string]$Sha256) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    if ([uint64](Get-Item -LiteralPath $Path).Length -ne $Size) { return $false }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $Sha256
}

New-Item -ItemType Directory -Path $downloadRoot -Force | Out-Null
if (-not (Test-PinnedFile $binary $expectedBinarySize $expectedBinarySha256)) {
    if (-not (Test-PinnedFile $archive $expectedArchiveSize $expectedArchiveSha256)) {
        $temporary = "$archive.download"
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $url -OutFile $temporary -UseBasicParsing
        if (-not (Test-PinnedFile $temporary $expectedArchiveSize $expectedArchiveSha256)) {
            Remove-Item -LiteralPath $temporary -Force
            throw "downloaded archive does not match the pinned size and SHA-256: $asset"
        }
        Move-Item -LiteralPath $temporary -Destination $archive -Force
    }

    $extractDirectory = Join-Path $downloadRoot 'extract'
    if (Test-Path -LiteralPath $extractDirectory) {
        Remove-Item -LiteralPath $extractDirectory -Recurse -Force
    }
    Expand-Archive -LiteralPath $archive -DestinationPath $extractDirectory
    $extracted = @(Get-ChildItem -LiteralPath $extractDirectory -File -Filter 'mihomo-windows-*.exe')
    if ($extracted.Count -ne 1) {
        throw 'archive must contain exactly one mihomo-windows executable'
    }
    if (-not (Test-PinnedFile $extracted[0].FullName $expectedBinarySize $expectedBinarySha256)) {
        throw 'extracted engine does not match engines.lock.json'
    }
    Move-Item -LiteralPath $extracted[0].FullName -Destination $binary -Force
    Remove-Item -LiteralPath $extractDirectory -Recurse -Force
}

Write-Output "mihomo=$binary"
Write-Output "sha256=$expectedBinarySha256"
