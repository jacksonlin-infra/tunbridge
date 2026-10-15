#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_directory/.." && pwd)

if [ "$(/usr/bin/uname -s)" != "Darwin" ]; then
    echo "error: macOS artifacts must be built on macOS" >&2
    exit 1
fi

requested_target=${TUNBRIDGE_MACOS_TARGET:-}
if [ -n "$requested_target" ]; then
    case "$requested_target" in
        aarch64-apple-darwin|x86_64-apple-darwin) target_triple=$requested_target ;;
        *)
            echo "error: TUNBRIDGE_MACOS_TARGET must be aarch64-apple-darwin or x86_64-apple-darwin" >&2
            exit 1
            ;;
    esac
else
    case "$(/usr/bin/uname -m)" in
        arm64) target_triple=aarch64-apple-darwin ;;
        x86_64) target_triple=x86_64-apple-darwin ;;
        *)
            echo "error: unsupported macOS build architecture" >&2
            exit 1
            ;;
    esac
fi

target_output_directory=$repository_root/target/$target_triple/release
app_bundle=$target_output_directory/bundle/macos/TunBridge.app
artifact_directory=$target_output_directory/bundle/macos
case "$target_triple" in
    aarch64-apple-darwin) architecture=arm64 ;;
    x86_64-apple-darwin) architecture=x86_64 ;;
esac

npm --prefix "$repository_root/apps/desktop" run bundle:macos:candidate
"$repository_root/scripts/ci/check-macos-bundle.sh" "$app_bundle" "$architecture"

version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' \
    "$app_bundle/Contents/Info.plist")
dmg="$artifact_directory/TunBridge-$version-$architecture.dmg"
pkg="$artifact_directory/TunBridge-$version-$architecture.pkg"

/usr/bin/hdiutil create -volname TunBridge -srcfolder "$app_bundle" \
    -ov -format UDZO "$dmg"
/usr/bin/pkgbuild --component "$app_bundle" --install-location /Applications \
    --identifier com.tunbridge.desktop.pkg --version "$version" "$pkg"

echo "macos_artifacts=ok app=$app_bundle dmg=$dmg pkg=$pkg signing=ad-hoc candidate=true"
echo "macos_release_ready=false reason=Developer-ID-notarization-required"
