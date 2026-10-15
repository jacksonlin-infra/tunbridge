# Linux

Targets: Ubuntu 24.04 and 26.04 x86_64 (DEB), and Omarchy 4 x86_64 (pacman package). Both use the same
service and UI.

- `crates/tunbridge-service-linux` — the hardened systemd system service. It listens on an AF_UNIX socket under
  `/run/tunbridge`, identifies callers by kernel peer credentials, owns the Mihomo engine and TUN, and keeps a
  root-owned journal for crash and reboot recovery.
- `crates/tunbridge-platform-linux` — the Linux parts of the desktop host: XDG paths, Secret Service
  credentials, `/proc` listener discovery and diagnostics.
- `crates/tunbridge-setup-linux` — the fixed maintenance helper used for engine updates.
- `packaging/` — DEB and pacman packaging.

A local proxy client is kept out of the tunnel by placing its process family in a transient systemd scope and
routing that scope's cgroup around the TUN with an exact nftables mark and policy rule. Only that scope bypasses
the tunnel; other applications of the same user stay on it.

Package scripts refuse to upgrade while the installed desktop is running, restart the service after an
upgrade, and confirm that `/proc/<pid>/exe` points to the newly installed binary. The packages depend on
`iproute2`, `nftables` and `systemd`.

Build instructions: [docs/building.md](../../docs/building.md).
