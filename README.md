# TunBridge

[简体中文](README.zh-CN.md)

TunBridge puts a system-wide TUN in front of an HTTP(S) or SOCKS5 proxy you already have, so that every
application — Git, SSH, package managers, AI CLIs, containers, native apps — uses it without per-app proxy
settings.

```text
applications → system network stack → TunBridge TUN → managed Mihomo engine
                                                     ├→ 127.0.0.1 HTTP/SOCKS5 of your existing proxy client
                                                     └→ a remote HTTP(S)/SOCKS5 endpoint you enter by hand
```

TunBridge does **not** provide proxy servers, subscriptions or node lists, does not scan your network, and
does not inspect TLS traffic. It only routes traffic to the upstream you choose.

## Features

- **Local upstream discovery.** Finds the loopback listener of a running proxy client and verifies which
  process owns it before using it.
- **Remote upstreams (experimental).** HTTP(S) and SOCKS5 endpoints on your LAN or the internet, with
  credentials kept in the system credential store (Credential Manager, Secret Service or Keychain).
- **Fails closed.** Once the tunnel is on, only an explicit user action turns it off. If the upstream, the
  engine or the UI fails, traffic stays blocked and you are notified instead of silently going direct.
- **Least privilege.** A small privileged service (Windows service, systemd service, macOS helper) owns the
  TUN, routes and DNS. The desktop UI runs as the user and can only send a fixed set of typed commands.
- **Observability.** Traffic, connections, Mihomo logs, tunnel events and connectivity diagnostics.
- Light/dark themes; English, 简体中文, 繁體中文 and 日本語.

## Platforms

| Platform | Package | Status |
| --- | --- | --- |
| Windows 11 x86_64 | NSIS setup `.exe` | Beta, not code-signed |
| Ubuntu 24.04 / 26.04 x86_64 | `.deb` | Beta |
| Omarchy 4 x86_64 (Arch-based) | pacman `.pkg.tar.zst` | Beta |
| macOS 12+ Apple silicon and Intel | `.dmg` / `.pkg` | Preview: ad-hoc signed, not notarized |

All platforms share one version number and one release. Download the package for your platform from
[Releases](https://github.com/jacksonlin-infra/tunbridge/releases) and check it against `SHA256SUMS`.

Because the packages are not signed yet, Windows SmartScreen and macOS Gatekeeper will warn before the first
launch. On macOS, open the app once from Finder with right-click → Open.

The app checks this Releases page for a newer version and opens it for you; it does not install updates by
itself.

## How it works

TunBridge runs [Mihomo](https://github.com/MetaCubeX/mihomo) as a managed engine. The privileged service:

1. verifies that the bundled engine matches its pinned size and SHA-256;
2. renders a fixed-shape Mihomo configuration from a typed profile (the UI never supplies raw YAML, paths,
   URLs or process IDs);
3. keeps the upstream's own connections out of the tunnel so traffic cannot loop back into it;
4. records everything it changes in a root/SYSTEM-owned journal, so a crash or reboot can be recovered
   exactly, without guessing or sweeping by process name.

See [docs/architecture.md](docs/architecture.md) and [docs/security-model.md](docs/security-model.md).

## Building from source

Requirements: Rust (see `rust-toolchain.toml`), Node.js 24 and [`just`](https://github.com/casey/just).

```bash
npm --prefix apps/desktop ci
just fmt-check
just contract-test
just ui-test
just ui-build
```

Installers must be built on their own platform. See [docs/building.md](docs/building.md).

## Contributing and security

- Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.
- Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in public issues.

## License

TunBridge is licensed under the [GNU General Public License v3.0 or later](LICENSE). The packages include
Mihomo, which is licensed under GPL-3.0; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

TunBridge is an independent project and is not affiliated with Mihomo, Clash or any proxy provider.
