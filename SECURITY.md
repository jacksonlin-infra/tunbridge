# Security policy

TunBridge runs a privileged service that changes routes, DNS and firewall state. Please report security
problems privately so they can be fixed before they are disclosed.

## Reporting

Use GitHub's private vulnerability reporting:
[Report a vulnerability](https://github.com/jacksonlin-infra/tunbridge/security/advisories/new).

Please include:

- the TunBridge version and platform;
- what an attacker needs (local standard user, another user on the same machine, network position);
- steps to reproduce, or a proof of concept;
- the impact you observed.

Do not open a public issue or pull request for a vulnerability, and do not include real proxy credentials or
production logs in a report.

You should get a first reply within 7 days. Once a fix is released, the advisory is published with credit to
the reporter unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes.

## Scope

In scope: anything that lets a caller make the privileged service or helper do more than its documented
commands, bypass caller or ownership checks, run or replace an engine, read or write files, leak credentials,
or leave the network in a state that TunBridge cannot recover. See [docs/security-model.md](docs/security-model.md).

Out of scope: attacks that already require administrator or root rights, vulnerabilities in a third-party
proxy client or server, and missing code signing (a known limitation of the current packages).
