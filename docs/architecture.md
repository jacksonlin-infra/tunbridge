# Architecture

TunBridge has two halves: an unprivileged desktop app, and a small privileged service that is the only
part allowed to change the network.

```text
React UI (apps/desktop/src)
  │  Tauri commands with bounded, typed inputs
  ▼
Desktop host (apps/desktop/src-tauri)        runs as the user
  │  profiles, credentials, discovery, diagnostics, tunnel event log
  │
  │  authenticated local IPC
  │    Windows: named pipe   Linux: AF_UNIX socket   macOS: XPC
  ▼
Privileged service (crates/tunbridge-service + platforms/*)   SYSTEM / root
  │  state machine, owner lease, watchdog, crash journal
  ├─ renders the Mihomo configuration from a typed profile
  ├─ starts and supervises the pinned Mihomo engine (TUN, DNS, controller)
  └─ applies and records platform network effects (routes, DNS, firewall rules)
```

## Repository layout

| Path | Contents |
| --- | --- |
| `apps/desktop` | React/Vite UI and the Tauri desktop host |
| `crates/tunbridge-core` | Profiles, upstream model, Mihomo config rendering, discovery and network state |
| `crates/tunbridge-service` | Platform-neutral service protocol, state machine, lease and watchdog policy |
| `crates/tunbridge-desktop-contract` | Command surface shared by the UI host on every platform |
| `crates/tunbridge-setup`, `crates/tunbridge-cli` | Windows setup transaction and a command-line client |
| `platforms/windows` | Windows service (SCM), named pipe, Credential Manager, NSIS setup |
| `platforms/linux` | systemd service, AF_UNIX transport, Secret Service, nftables, DEB and pacman packages |
| `platforms/macos` | Privileged helper, XPC, Keychain, Darwin routes/DNS/packet filter, DMG/PKG |
| `scripts` | Build, packaging, version and static release checks |

Shared crates never depend on a platform crate. Anything that needs privileges lives in the platform service,
setup or helper.

## Upstreams

A profile names exactly one upstream, which is one of two explicit kinds:

- **Local listener** — a proxy client on `127.0.0.1` or `::1`. The desktop discovers listeners; the service
  proves again, by itself, which process owns the socket before every start.
- **Remote server** — an HTTP(S) or SOCKS5 endpoint entered by hand. The service resolves it, picks one
  address and pins it for the session. Hostnames and IPs typed by the user are treated as intent, never as a
  routing fact.

Credentials are kept in the platform credential store and sent to the service only as part of a typed start
request. They are never logged.

## Keeping the upstream out of the tunnel

The upstream's own connections must not enter the TUN, or traffic would loop. TunBridge separates two
things that are easy to confuse:

- **Traffic bypass rules** decide which ordinary destinations go direct inside Mihomo (for example private
  address ranges).
- **Transport escape** keeps the upstream's transport out of the tunnel. It is computed by the service for
  each session and is never edited by the user.

How the escape is built depends on the platform: exact `/32` or `/128` exclusions for the pinned remote
address, a dedicated cgroup scope with an nftables mark and policy rule for local proxy clients on Linux, and
exact physical routes installed by the helper on macOS. Each effect is recorded before it is applied and removed
only if it still matches the record.

## Lifecycle

```text
Stopped ──start──▶ Starting ──verified──▶ Running ──stop──▶ Stopping ──▶ Stopped
                      │                      │
                      └──── failure ─────────┴──▶ Recovering / Faulted (traffic stays blocked)
```

A start succeeds only after the engine, the TUN device, routes, DNS and a data-path check have all been
verified. Any earlier failure rolls back exactly what was recorded.

Once running, **only an explicit user action stops the tunnel.** When the upstream becomes unavailable, the
session reports itself as degraded and traffic stays blocked. If the engine exits or the TUN disappears, the
service restarts the engine; after repeated failures it holds the session in a faulted state and asks the
user. Quitting the UI, logging out, or a UI crash leave the tunnel running; the UI takes it over again on
the next launch. If ownership can no longer be proven, the service does nothing destructive and waits for an
explicit recovery.

## Engine

Mihomo runs as a child of the service with a fixed executable, fixed arguments and a configuration written to
a protected directory. Before each start the service checks the engine's size and SHA-256 against the pinned
manifest. The controller is bound to loopback and protected by a random per-session secret.

On Windows and Linux, the engine can be updated independently; the update keeps the active profile, verifies
the new engine, and restores the profile. On macOS the engine is updated together with the app.

## Versions and releases

Windows, Linux and macOS ship one product version from one tag, `tunbridge-desktop-v<version>`. Each release
attaches a `tunbridge-update.json` manifest; the app reads it to tell the user that a newer version exists.
