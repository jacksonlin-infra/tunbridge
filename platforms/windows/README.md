# Windows

Target: Windows 11 x86_64.

- `crates/tunbridge-service-windows` — the LocalSystem service registered with the Service Control Manager.
  It serves a protected local named pipe, owns the Mihomo engine and the Wintun adapter, and records every
  session in a protected state directory under ProgramData.
- `crates/tunbridge-platform-windows` — the Windows parts of the desktop host: Credential Manager, local
  listener discovery, diagnostics and the engine update client.
- `packaging/` — the NSIS setup. `build-desktop-app.ps1` is the single build entry point; see
  [docs/building.md](../../docs/building.md).

Setup asks a running TunBridge desktop to exit safely, stops and recovers an active tunnel, replaces the
installed product generation as a whole, and verifies the new service before finishing. Installing a fixed
build always requires a higher version number.
