# Platform implementations

This directory owns operating-system integration. Shared product behavior stays
in `apps/desktop` and the root `crates/`.

- `windows/`: the accepted Windows 0.2.0 adapters, service host, setup, packaging,
  and regression entrypoints.
- `linux/`: Ubuntu-first adapters, systemd service, DEB packaging, and acceptance.
- `macos/`: Monterey 12.7.6-compatible adapters, privileged helper, packaging,
  and isolated acceptance.

Platform crates may depend on shared crates. Shared crates must not depend on a
platform Cargo package. During P1, shared crates can include relocated platform
source through an explicit `#[path]` module to preserve the accepted public API;
P2 replaces those compatibility seams with platform adapter contracts.
