[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$workspaceManifest = Get-Content -LiteralPath (Join-Path $root 'Cargo.toml') -Raw
$versionMatch = [regex]::Match($workspaceManifest, '(?m)^version\s*=\s*"([^"]+)"\s*$')
if (-not $versionMatch.Success) {
    throw 'workspace product version is missing'
}
$productVersion = $versionMatch.Groups[1].Value
$desktop = Join-Path $root 'apps\desktop'
$target = Join-Path $root 'target\desktop-app'
$release = Join-Path $target 'release'
$distributionRoot = [IO.Path]::GetFullPath((Join-Path $root 'target\dist'))
$distribution = [IO.Path]::GetFullPath(
    (Join-Path $distributionRoot "tunbridge-desktop-$productVersion")
)
$distributionArchive = "$distribution.zip"
$setupBundle = Join-Path $distributionRoot "TunBridge-$productVersion-windows-x86_64-setup.exe"
$executable = Join-Path $release 'tunbridge-desktop.exe'
$setup = Join-Path $release 'tunbridge-setup.exe'
$service = Join-Path $release 'tunbridge-service.exe'
$cli = Join-Path $release 'tunbridge.exe'
$engine = Join-Path $root 'target\windows-engine\mihomo.exe'
$engineLock = Join-Path $root 'engines.lock.json'
$packagedEngine = Join-Path $release 'mihomo.exe'
$packagedEngineLock = Join-Path $release 'engines.lock.json'
$packageManifest = Join-Path $release 'product-package.json'
$npm = (Get-Command npm.cmd -ErrorAction Stop).Source
$cargo = (Get-Command cargo.exe -ErrorAction Stop).Source
$previousTarget = $env:CARGO_TARGET_DIR
$previousJobs = $env:CARGO_BUILD_JOBS
$previousSetupHash = $env:TUNBRIDGE_SETUP_SHA256
$previousRustFlags = $env:RUSTFLAGS

& (Join-Path $root 'scripts\fetch-windows-mihomo.ps1') | Out-Host

try {
    $env:CARGO_TARGET_DIR = $target
    # A clean target links many build scripts; serialize them to avoid the
    # intermittent resource-related MSVC linker exits seen under parallel load.
    $env:CARGO_BUILD_JOBS = '1'
    # The setup executable runs before any product files are installed. Link the
    # MSVC runtime into every Rust executable so a clean Windows 11 machine can
    # launch setup, service, CLI, and Desktop without a VC++ redistributable.
    $env:RUSTFLAGS = "$previousRustFlags -C target-feature=+crt-static".Trim()
    Push-Location $root
    try {
        & $cargo build --release -p tunbridge-setup -p tunbridge-service -p tunbridge-cli `
            --features tunbridge-service/production-mihomo-logs-v4
        if ($LASTEXITCODE -ne 0) {
            throw "product support binaries failed with exit code $LASTEXITCODE"
        }
    }
    finally {
        Pop-Location
    }
    if (-not (Test-Path -LiteralPath $setup -PathType Leaf)) {
        throw 'isolated desktop setup executable is missing after support build'
    }
    $env:TUNBRIDGE_SETUP_SHA256 = (Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash.ToLowerInvariant()
    Push-Location $desktop
    try {
        & $npm run tauri -- build --no-bundle
        if ($LASTEXITCODE -ne 0) {
            throw "Tauri build failed with exit code $LASTEXITCODE"
        }
    }
    finally {
        Pop-Location
    }
}
finally {
    $env:CARGO_TARGET_DIR = $previousTarget
    $env:CARGO_BUILD_JOBS = $previousJobs
    $env:TUNBRIDGE_SETUP_SHA256 = $previousSetupHash
    $env:RUSTFLAGS = $previousRustFlags
}

if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw 'isolated desktop executable is missing after Tauri build'
}
foreach ($required in @($setup, $service, $cli, $engine, $engineLock)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "desktop product package source is missing: $required"
    }
}

$crtCheck = Join-Path $root 'platforms\windows\packaging\check-crt-dependencies.ps1'
& $crtCheck -Executables @($executable, $setup, $service, $cli)
if ($LASTEXITCODE -ne 0) {
    throw "Windows CRT dependency check failed with exit code $LASTEXITCODE"
}

$engineManifest = Get-Content -LiteralPath $engineLock -Raw | ConvertFrom-Json
$engineFile = Get-Item -LiteralPath $engine
$engineHash = (Get-FileHash -LiteralPath $engine -Algorithm SHA256).Hash.ToLowerInvariant()
if ($engineManifest.schema_version -ne 1 -or $engineManifest.engine.filename -ne 'mihomo.exe' -or
    [uint64]$engineManifest.engine.size -ne [uint64]$engineFile.Length -or
    $engineManifest.engine.sha256 -cne $engineHash) {
    throw 'downloaded engine does not match the frozen engine manifest'
}

Copy-Item -LiteralPath $engine -Destination $packagedEngine -Force
Copy-Item -LiteralPath $engineLock -Destination $packagedEngineLock -Force

$payload = @(
    @{ filename = 'tunbridge-desktop.exe'; path = $executable },
    @{ filename = 'tunbridge-setup.exe'; path = $setup },
    @{ filename = 'tunbridge-service.exe'; path = $service },
    @{ filename = 'tunbridge.exe'; path = $cli },
    @{ filename = 'mihomo.exe'; path = $packagedEngine },
    @{ filename = 'engines.lock.json'; path = $packagedEngineLock }
)
$files = @($payload | ForEach-Object {
    $item = Get-Item -LiteralPath $_.path
    [ordered]@{
        filename = $_.filename
        size = [uint64]$item.Length
        sha256 = (Get-FileHash -LiteralPath $_.path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
})
$manifest = [ordered]@{
    schema_version = 1
    product_version = $productVersion
    service_feature = 'production-mihomo-logs-v4'
    service_protocol_version = 4
    service_capabilities = @(
        'status',
        'start',
        'stop',
        'recover',
        'lease',
        'observe_local_traffic',
        'close_owned_connections',
        'remote_upstream',
        'observe_mihomo_logs'
    )
    files = $files
}
$utf8NoBom = New-Object Text.UTF8Encoding($false)
[IO.File]::WriteAllText($packageManifest, ($manifest | ConvertTo-Json -Depth 6), $utf8NoBom)

New-Item -ItemType Directory -Path $distributionRoot -Force | Out-Null
$distributionBoundary = $distributionRoot + [IO.Path]::DirectorySeparatorChar
if (-not $distribution.StartsWith($distributionBoundary, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'distribution directory escaped target\dist'
}
if (Test-Path -LiteralPath $distribution) {
    Remove-Item -LiteralPath $distribution -Recurse -Force
}
New-Item -ItemType Directory -Path $distribution | Out-Null
$distributionFiles = @(
    $executable,
    $setup,
    $service,
    $cli,
    $packagedEngine,
    $packagedEngineLock,
    $packageManifest
)
foreach ($source in $distributionFiles) {
    Copy-Item -LiteralPath $source -Destination $distribution
}
$expectedDistributionNames = @(
    'engines.lock.json',
    'mihomo.exe',
    'product-package.json',
    'tunbridge-desktop.exe',
    'tunbridge-service.exe',
    'tunbridge-setup.exe',
    'tunbridge.exe'
)
$actualDistributionNames = @(
    Get-ChildItem -LiteralPath $distribution -File |
        Select-Object -ExpandProperty Name |
        Sort-Object
)
if (($actualDistributionNames -join ',') -cne (($expectedDistributionNames | Sort-Object) -join ',')) {
    throw 'clean distribution contains missing or unexpected files'
}
if (Test-Path -LiteralPath $distributionArchive -PathType Leaf) {
    Remove-Item -LiteralPath $distributionArchive -Force
}
$archiveInputs = @(Get-ChildItem -LiteralPath $distribution -File | Select-Object -ExpandProperty FullName)
Compress-Archive -LiteralPath $archiveInputs -DestinationPath $distributionArchive -CompressionLevel Optimal

$setupBuilder = Join-Path $root 'platforms\windows\packaging\build-windows-setup.ps1'
& $setupBuilder -PackageDirectory $distribution -OutputDirectory $distributionRoot -ProductVersion $productVersion
if (-not (Test-Path -LiteralPath $setupBundle -PathType Leaf)) {
    throw 'Windows Setup bundle is missing after packaging'
}

[ordered]@{
    schemaVersion = 1
    ok = $true
    executable = [IO.Path]::GetFullPath($executable)
    sha256 = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant()
    internalSetup = [IO.Path]::GetFullPath($setup)
    internalSetupSha256 = (Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash.ToLowerInvariant()
    installer = [IO.Path]::GetFullPath($setupBundle)
    installerSha256 = (Get-FileHash -LiteralPath $setupBundle -Algorithm SHA256).Hash.ToLowerInvariant()
    installerCreated = $true
    packageManifest = [IO.Path]::GetFullPath($packageManifest)
    distributionDirectory = $distribution
    distributionArchive = [IO.Path]::GetFullPath($distributionArchive)
    distributionFiles = $actualDistributionNames
} | ConvertTo-Json
