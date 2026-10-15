# Changelog

All notable changes to TunBridge are recorded here. The project follows
[Semantic Versioning](https://semver.org/); every platform shares one version.

## [0.4.1] - Unreleased

First public release. Earlier versions were internal builds.

### Changed

- The app looks for updates in the public repository, `jacksonlin-infra/tunbridge`. Installations of 0.4.0
  and earlier cannot see new versions; install 0.4.1 once by hand.
- The Windows build downloads and verifies its pinned Mihomo engine itself
  (`scripts/fetch-windows-mihomo.ps1`), like the Linux and macOS builds.

### Fixed

- Traffic and connection data no longer disappear when Mihomo has many live connections. The services
  truncated the controller's connection list at 512 KiB (macOS), 1 MiB (Windows) or 2 MiB (Linux), which
  broke parsing from roughly 650 to 2,700 connections; all platforms now accept up to 16 MiB.
- Linux: stopping the tunnel while thousands of connections were open could leave the session faulted
  ("process identity could not be verified") because the engine was still closing its sockets. Stop now
  waits for the engine to finish exiting.

### Added

- License, third-party notices, contribution guide and security policy.

### Known issues

- Starting again immediately after stopping can fail with a configuration validation error. The network is
  rolled back; starting again usually succeeds. On Linux, sending one request through the proxy client before
  starting avoids it.
- Packages are not code-signed; macOS packages are ad-hoc signed and not notarized.

[0.4.1]: https://github.com/jacksonlin-infra/tunbridge/releases/tag/tunbridge-desktop-v0.4.1
