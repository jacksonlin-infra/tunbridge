# Cross-platform quality entrypoints. Privileged, network-changing, installer,
# and ignored acceptance tests are intentionally excluded from `check`.

npm := if os_family() == "windows" { "npm.cmd" } else { "npm" }

default:
    @just --list

fmt-check:
    cargo fmt --all -- --check

lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
    cargo test --workspace

test-all-features:
    cargo test --workspace --all-features

[working-directory("apps/desktop")]
ui-test:
    {{npm}} test -- --configLoader runner

[working-directory("apps/desktop")]
ui-build:
    {{npm}} run build -- --configLoader runner

[working-directory("apps/desktop")]
ui-dev-mock:
    {{npm}} run dev:mock

[working-directory("apps/desktop")]
ui-release-surface:
    {{npm}} run check:release-surface

[working-directory("apps/desktop")]
macos-compat:
    {{npm}} run check:macos-compat

version-sync:
    {{npm}} --prefix apps/desktop run check:version-sync

release-tag-check:
    {{npm}} --prefix apps/desktop run check:release-tag

release-manifest-test:
    {{npm}} --prefix apps/desktop run test:release-manifest

windows-setup-check:
    {{npm}} --prefix apps/desktop run check:windows-setup

omarchy-package-check:
    scripts/check-linux-desktop-omarchy.sh

third-party-notices-check:
    node scripts/release/third-party-notices.mjs --check

contract-test:
    cargo test -p tunbridge-desktop -p tunbridge-desktop-contract --all-features
    {{npm}} --prefix apps/desktop test -- --configLoader runner

check: fmt-check lint test test-all-features ui-test ui-build ui-release-surface macos-compat version-sync release-tag-check release-manifest-test windows-setup-check
