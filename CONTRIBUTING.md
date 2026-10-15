# Contributing to TunBridge

Thanks for helping. TunBridge changes the network of the machine it runs on, so changes are reviewed with
safety first.

## Before you start

- For anything larger than a small fix, open an issue first so the approach can be agreed on.
- Security problems go through [SECURITY.md](SECURITY.md), never through a public issue or pull request.
- Read [docs/architecture.md](docs/architecture.md) and [docs/security-model.md](docs/security-model.md).

## Ground rules

- **The tunnel only stops on an explicit user action.** No change may add a path where a fault, timeout,
  crash or UI exit silently turns the tunnel off and lets traffic go direct.
- **Privileged code stays at the boundary.** Only the platform service, setup or helper may change routes,
  DNS, firewall state or processes. The UI and desktop host must never choose an executable, a file path, a
  URL, a PID or a cleanup target for the service.
- **Fail closed.** If ownership or identity cannot be proven, refuse and report; do not guess or clean up by
  name.
- **Shared crates stay platform-neutral.** Code under `crates/` must not depend on `platforms/`.
- **No secrets or real data.** Do not commit proxy servers, subscriptions, credentials, signing keys,
  certificates or real logs. Use documentation addresses (`192.0.2.0/24`, `example.com`) in tests.
- Do not change the product version in a pull request; maintainers do that at release time.

## Development

See [docs/building.md](docs/building.md). Before opening a pull request, run at least:

```bash
cargo fmt --all -- --check
just contract-test
just ui-test
npm --prefix apps/desktop run check:version-sync
git diff --check
```

Run `just check` on the platform your change affects. If you change platform code you cannot build
locally, say so in the pull request; CI builds Windows, Ubuntu and macOS.

Do not claim that an installer or a privileged flow works unless you built and ran it on that platform.
Describe what you tested and on which OS version.

## Pull requests

- Keep each pull request focused on one change, and add tests for new behaviour and for every new refusal
  path.
- Write commit messages in the imperative mood (`fix(linux): ...`, `feat(ui): ...`).
- Sign off every commit to certify the [Developer Certificate of Origin](https://developercertificate.org/):

  ```bash
  git commit -s
  ```

By contributing you agree that your contribution is licensed under the GNU General Public License v3.0 or
later, the same license as the project.

## How changes are released

Development happens in a private repository, and each release is published here as a single commit. Pull
requests merged here are merged back into development, so your commits are kept; they appear in this
repository's history and in the next release.
