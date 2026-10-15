# Security model

The privileged service can change routes, DNS and firewall state and can start processes as SYSTEM or root.
Its design goal is that it can never be turned into a general-purpose tool for doing so.

## Goals

1. A standard user can start, stop, inspect and recover TunBridge without elevating again after installation.
2. The service never runs arbitrary commands, reads or writes arbitrary files, terminates arbitrary processes,
   or applies arbitrary network changes.
3. Only the engine pinned by the installed package runs, and only after its size and SHA-256 are verified.
4. The service only stops processes and removes network effects that it recorded itself and can still prove
   it owns. PID reuse, a damaged state file or a failed query means "do nothing destructive".
5. Unauthorized callers, malformed or oversized messages, replays and conflicting operations get a stable
   error and cause no privileged side effect.
6. Logs and error messages never contain proxy passwords, controller secrets, full user paths or raw requests.

## Out of scope

- Attackers who already have administrator or root rights on the machine.
- Remote control: the IPC endpoints accept local callers only.
- Plugins, custom engines, custom engine arguments or user-supplied Mihomo configuration files.
- Installing, upgrading and uninstalling, which remain administrator operations performed by the platform's
  installer.

## Trust boundary

```text
desktop UI / CLI (standard user)        untrusted input
        │
        ▼  local IPC: access control + kernel-provided caller identity + bounded framing
privileged service (SYSTEM / root)
        ├─ protected install directory: service, engine, engine manifest
        ├─ protected data directory: rendered config, session state, crash journal
        └─ Mihomo child process: fixed image, fixed arguments, generated config
```

The caller's identity always comes from the operating system, never from the message:

| Platform | Transport | Caller identity |
| --- | --- | --- |
| Windows | Named pipe with a protected DACL that refuses remote clients | Client token: SID, session, integrity level |
| Linux | AF_UNIX socket under `/run/tunbridge` | Kernel peer credentials (UID, PID) |
| macOS | XPC to a helper installed with ServiceManagement | Audit token and code-signing requirement |

## Protocol rules

- Messages are length-prefixed and capped in size. The length is checked before parsing.
- The first message negotiates the protocol version; there is no silent downgrade.
- Payloads are strict JSON: unknown fields, duplicate keys and out-of-range values are rejected.
- Each connection is bound to a server nonce and a strictly increasing sequence number, so frames cannot be
  replayed or moved to another connection.
- Commands come from a fixed list (status, start, stop, recover, lease and read-only observation). None of them
  takes an executable, a file path, a URL, a route, an interface name or a PID.

## Ownership

The first successful start records its owner. The owner can stop and recover the session; other standard
users can only read a redacted status. Every state change is persisted atomically, together with an operation
ID, before any side effect happens. A state file that is damaged or from an unknown version is never treated as
"stopped".

The engine is identified by PID, start time, canonical image path and hash. Before stopping or recovering, the
service re-checks all of them; if any check fails, it refuses to act.

## Engine integrity

The service derives the install directory from its own verified location, not from the working directory,
`PATH`, environment variables or the caller. It refuses reparse points or symlinks and directories that a
standard user can write to, checks the manifest and the engine's size and SHA-256, renders the configuration
itself, and validates it with the engine before starting it.

## Credentials

Proxy credentials live in the user's credential store (Windows Credential Manager, Secret Service on Linux,
login Keychain on macOS). The desktop host reads them only to build a start request; the service keeps them
in memory for the session and writes them only into the protected engine configuration.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
