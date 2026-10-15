#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_directory/.." && pwd)
product_version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "$repository_root/Cargo.toml" | head -n 1)
if [ -z "$product_version" ]; then
    echo "Workspace product version is missing." >&2
    exit 1
fi
if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
    echo "Omarchy packages require an x86_64 Linux host." >&2
    exit 1
fi
if [ ! -r /etc/os-release ] ||
    ! grep -Eq '^ID=(omarchy|arch)$|^ID_LIKE=.*arch' /etc/os-release; then
    echo "Omarchy packages must be built on Omarchy or Arch Linux." >&2
    exit 1
fi
for command in cargo npm makepkg install sed sha256sum; do
    command -v "$command" >/dev/null || {
        echo "Required build command is missing: $command" >&2
        exit 1
    }
done

cd "$repository_root"
"$repository_root/scripts/check-linux-desktop-omarchy.sh"
"$repository_root/scripts/fetch-linux-mihomo.sh"
cargo build --release -p tunbridge-service-linux
cargo build --release -p tunbridge-setup-linux --features pacman-package \
    --bin tunbridge-maintenance-linux
cd "$repository_root/apps/desktop"
npm run build -- --configLoader runner
npm run check:release-surface
npm run tauri -- build --no-bundle --features omarchy-package

build_root="$repository_root/target/omarchy-package"
payload="$build_root/payload"
rm -rf -- "$build_root"
install -d \
    "$payload/usr/bin" \
    "$payload/usr/libexec/tunbridge" \
    "$payload/usr/share/libalpm/hooks" \
    "$payload/usr/lib/systemd/system" \
    "$payload/usr/share/applications" \
    "$payload/usr/share/icons/hicolor/512x512/apps" \
    "$payload/usr/share/tunbridge"
install -m 0755 "$repository_root/target/release/tunbridge-desktop" \
    "$payload/usr/bin/tunbridge-desktop"
install -m 0755 "$repository_root/target/release/tunbridge-service-linux" \
    "$payload/usr/libexec/tunbridge/tunbridge-service-linux"
install -m 0755 "$repository_root/target/release/tunbridge-maintenance-linux" \
    "$payload/usr/libexec/tunbridge/tunbridge-maintenance-linux"
install -m 0755 "$repository_root/platforms/linux/packaging/arch/tunbridge-package-guard" \
    "$payload/usr/libexec/tunbridge/tunbridge-package-guard"
install -m 0755 "$repository_root/target/release/mihomo" \
    "$payload/usr/libexec/tunbridge/mihomo"
install -m 0644 "$repository_root/platforms/linux/packaging/systemd/tunbridge.service" \
    "$payload/usr/lib/systemd/system/tunbridge.service"
install -m 0644 "$repository_root/platforms/linux/packaging/deb/engine-manifest.json" \
    "$payload/usr/share/tunbridge/engine-manifest.json"
install -m 0644 "$repository_root/platforms/linux/packaging/arch/linux-service-layout.json" \
    "$payload/usr/share/tunbridge/linux-service-layout.json"
install -m 0644 "$repository_root/platforms/linux/packaging/arch/tunbridge.desktop" \
    "$payload/usr/share/applications/tunbridge.desktop"
install -m 0644 \
    "$repository_root/platforms/linux/packaging/arch/tunbridge-desktop-upgrade-guard.hook" \
    "$payload/usr/share/libalpm/hooks/tunbridge-desktop-upgrade-guard.hook"
install -m 0644 "$repository_root/apps/desktop/src-tauri/icons/icon.png" \
    "$payload/usr/share/icons/hicolor/512x512/apps/tunbridge.png"
sed "s/@PRODUCT_VERSION@/$product_version/g" \
    "$repository_root/platforms/linux/packaging/arch/PKGBUILD.in" >"$build_root/PKGBUILD"
install -m 0644 "$repository_root/platforms/linux/packaging/arch/tunbridge-desktop.install" \
    "$build_root/tunbridge-desktop.install"

cd "$build_root"
SOURCE_DATE_EPOCH=$(git -C "$repository_root" log -1 --format=%ct)
export SOURCE_DATE_EPOCH
makepkg --force --nodeps --cleanbuild --clean
set -- "$build_root"/tunbridge-desktop-"$product_version"-1-x86_64.pkg.tar.zst
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
    echo "Expected exactly one Omarchy package artifact." >&2
    exit 1
fi

artifact_directory="$repository_root/artifacts/releases/$product_version"
install -d "$artifact_directory"
rm -f -- "$artifact_directory"/tunbridge-desktop-*-x86_64.pkg.tar.zst \
    "$artifact_directory/SHA256SUMS.omarchy"
install -m 0644 "$1" "$artifact_directory/$(basename "$1")"
(
    cd "$artifact_directory"
    sha256sum "$(basename "$1")" >SHA256SUMS.omarchy
)
"$repository_root/scripts/verify-linux-desktop-omarchy.sh" \
    "$artifact_directory/$(basename "$1")"

printf 'artifact=%s/%s\n' "$artifact_directory" "$(basename "$1")"
printf 'checksums=%s/SHA256SUMS.omarchy\n' "$artifact_directory"
