#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
product_version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "$repository_root/Cargo.toml" | head -n 1)
if [ -z "$product_version" ]; then
    echo "Workspace product version is missing." >&2
    exit 1
fi

if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
    echo "Linux DEB builds require an x86_64 Linux host." >&2
    exit 1
fi

cd "$repository_root"
"$repository_root/scripts/fetch-linux-mihomo.sh"
cargo build --release -p tunbridge-service-linux
cargo build --release -p tunbridge-setup-linux --bin tunbridge-maintenance-linux

bundle_directory="$repository_root/target/release/bundle/deb"
if [ -d "$bundle_directory" ]; then
    rm -f -- "$bundle_directory"/*.deb
fi

cd "$repository_root/apps/desktop"
# Build the UI before inspecting it; a clean checkout has no dist yet.
npm run build -- --configLoader runner
npm run check:release-surface
npm run tauri -- build --bundles deb

set -- "$repository_root"/target/release/bundle/deb/*.deb
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
    echo "Expected exactly one Linux DEB artifact." >&2
    exit 1
fi

artifact_directory="$repository_root/artifacts/releases/$product_version"
mkdir -p "$artifact_directory"
rm -f -- "$artifact_directory"/*.deb "$artifact_directory/SHA256SUMS"
cp "$1" "$artifact_directory/"
cp "$repository_root/platforms/linux/packaging/deb/README-acceptance-zh-CN.md" \
    "$artifact_directory/"
(
    cd "$artifact_directory"
    sha256sum "$(basename "$1")" > SHA256SUMS
)

printf 'artifact=%s/%s\n' "$artifact_directory" "$(basename "$1")"
printf 'checksums=%s/SHA256SUMS\n' "$artifact_directory"
