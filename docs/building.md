# Building TunBridge

Installers are built natively on each target platform. Cross-compiling the release packages is not supported:
each one needs its own SDK, packaging tools and checks.

## Common requirements

- Rust toolchain from `rust-toolchain.toml`, with `rustfmt` and `clippy`.
- Node.js 24. UI dependencies are pinned by `apps/desktop/package-lock.json`.
- [`just`](https://github.com/casey/just) for the shared checks.

```bash
npm --prefix apps/desktop ci
just fmt-check       # cargo fmt --check
just contract-test   # shared service and desktop contracts
just ui-test         # UI unit tests
just ui-build        # UI production build
just version-sync    # every manifest carries the same product version
just check           # full gate: clippy, all workspace tests, UI and release static checks
```

`just check` needs the native dependencies of the platform you run it on. Tests that need administrator
rights, a real TUN device, an installer or network changes are never run by `just check`.

To work on the UI without a privileged service:

```bash
just ui-dev-mock
```

## Mihomo engine

Every package ships one pinned Mihomo build. The build scripts download it from the
[MetaCubeX/mihomo releases](https://github.com/MetaCubeX/mihomo/releases) and refuse to package it unless its
size and SHA-256 match the pinned values:

| Platform | Script | Pins |
| --- | --- | --- |
| Windows | `scripts/fetch-windows-mihomo.ps1` | `engines.lock.json` and the script |
| Linux | `scripts/fetch-linux-mihomo.sh` | the script |
| macOS | `scripts/fetch-macos-mihomo.mjs` | `platforms/macos/engine.lock.json` |

## Ubuntu (DEB)

Build on Ubuntu 24.04 or newer, x86_64. Install the native build dependencies first:

```bash
sudo apt-get install -y build-essential desktop-file-utils libwebkit2gtk-4.1-dev libgtk-3-dev \
  libayatana-appindicator3-dev librsvg2-dev libxdo-dev
scripts/build-linux-desktop-deb.sh
scripts/verify-linux-desktop-deb.sh artifacts/releases/<version>/TunBridge_<version>_amd64.deb
```

## Omarchy / Arch (pacman)

Build on Omarchy or Arch Linux, x86_64, with `base-devel` installed:

```bash
scripts/build-linux-desktop-omarchy.sh
scripts/verify-linux-desktop-omarchy.sh \
  artifacts/releases/<version>/tunbridge-desktop-<version>-1-x86_64.pkg.tar.zst
```

## macOS (DMG and PKG)

Build on macOS with Xcode command line tools. The deployment target is macOS 12.0.

```bash
scripts/build-macos-desktop-artifacts.sh
```

The script builds for the current architecture; set `TUNBRIDGE_MACOS_TARGET=x86_64-apple-darwin` or
`aarch64-apple-darwin` to choose one. Output goes to `target/<target>/release/bundle/macos/`. The result is
ad-hoc signed and not notarized.

## Windows (Setup EXE)

Build on Windows 11 x86_64 with the MSVC Rust toolchain, Visual Studio Build Tools and
[NSIS](https://nsis.sourceforge.io/) (`makensis.exe` on `PATH` or in the default install location). From
PowerShell:

```powershell
platforms\windows\packaging\build-desktop-app.ps1
```

The script downloads and verifies the engine, links the MSVC runtime statically, refuses any executable that
still depends on `VCRUNTIME140.dll`, and writes `target\dist\TunBridge-<version>-windows-x86_64-setup.exe`.

## Versions

Windows, Linux and macOS always share one product version. Change it only with:

```bash
node scripts/release/set-version.mjs <version>
cargo check --workspace
npm --prefix apps/desktop run check:version-sync
```

Release tags have the form `tunbridge-desktop-v<version>`.
