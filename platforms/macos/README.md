# macOS

Targets: macOS 12 or later on Apple silicon (arm64) and Intel (x86_64), built separately for each architecture.

- `crates/tunbridge-service-macos` — the privileged helper. It is installed with SMJobBless after the
  user approves it, accepts XPC connections only from the app whose code identity it pinned,
  owns the Mihomo engine and utun device, and applies exact routes, DNS settings and packet-filter rules that it
  records in a root-owned journal.
- `crates/tunbridge-platform-macos` — the macOS parts of the desktop host: login Keychain credentials, listener
  discovery and system information.
- `crates/tunbridge-setup-macos` — bundle inspection and helper registration.

The engine ships inside the app bundle and is provisioned by the helper; updating the app updates the engine.
Independent engine updates are not available on macOS.

Current packages are ad-hoc signed and not notarized. Because the helper pins the app's code identity, a
rebuilt app may need the service to be installed again from Settings.

Build instructions: [docs/building.md](../../docs/building.md).
