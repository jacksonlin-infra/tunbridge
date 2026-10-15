[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageDirectory,
    [string]$OutputDirectory = '',
    [string]$ProductVersion = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$PackageDirectory = [IO.Path]::GetFullPath($PackageDirectory)
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot 'target\dist'
}
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)

if ([string]::IsNullOrWhiteSpace($ProductVersion)) {
    $workspaceManifest = Get-Content -LiteralPath (Join-Path $repositoryRoot 'Cargo.toml') -Raw
    $versionMatch = [regex]::Match($workspaceManifest, '(?ms)\[workspace\.package\].*?^version\s*=\s*"([^"]+)"\s*$')
    if (-not $versionMatch.Success) {
        throw 'workspace product version is missing'
    }
    $ProductVersion = $versionMatch.Groups[1].Value
}
if ($ProductVersion -notmatch '^\d+\.\d+\.\d+$') {
    throw 'Windows stable Setup requires a three-component numeric product version'
}

$requiredFiles = @(
    'tunbridge-desktop.exe',
    'tunbridge-setup.exe',
    'tunbridge-service.exe',
    'tunbridge.exe',
    'mihomo.exe',
    'engines.lock.json',
    'product-package.json'
)
$actualFiles = @(Get-ChildItem -LiteralPath $PackageDirectory -File | ForEach-Object Name | Sort-Object)
if (($actualFiles -join ',') -cne (($requiredFiles | Sort-Object) -join ',')) {
    throw 'Windows Setup package directory must contain the exact seven-file product generation'
}

$makensis = Get-Command 'makensis.exe' -ErrorAction SilentlyContinue
if ($null -eq $makensis) {
    $candidate = Join-Path ${env:ProgramFiles(x86)} 'NSIS\makensis.exe'
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw 'makensis.exe is required to build the Windows Setup package'
    }
    $makensisPath = $candidate
} else {
    $makensisPath = $makensis.Source
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$output = Join-Path $OutputDirectory "TunBridge-$ProductVersion-windows-x86_64-setup.exe"
$script = Join-Path $PSScriptRoot 'TunBridgeSetup.nsi'
$icon = Join-Path $repositoryRoot 'apps\desktop\src-tauri\icons\icon.ico'
$fileVersion = "$ProductVersion.0"

& $makensisPath `
    "/DPRODUCT_VERSION=$ProductVersion" `
    "/DFILE_VERSION=$fileVersion" `
    "/DPACKAGE_DIR=$PackageDirectory" `
    "/DOUTPUT_FILE=$output" `
    "/DPRODUCT_ICON=$icon" `
    $script
if ($LASTEXITCODE -ne 0) {
    throw "makensis failed with exit code $LASTEXITCODE"
}
if (-not (Test-Path -LiteralPath $output -PathType Leaf)) {
    throw 'Windows Setup output is missing'
}

[ordered]@{
    schemaVersion = 1
    ok = $true
    productVersion = $ProductVersion
    installer = [IO.Path]::GetFullPath($output)
    sha256 = (Get-FileHash -LiteralPath $output -Algorithm SHA256).Hash.ToLowerInvariant()
    packageFiles = $actualFiles
    codeSigned = $false
} | ConvertTo-Json -Depth 4
