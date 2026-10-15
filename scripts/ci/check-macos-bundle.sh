#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: check-macos-bundle.sh <TunBridge.app> [arm64|x86_64]" >&2
    exit 2
fi

app_bundle=$1
expected_arch=${2:-$(/usr/bin/uname -m)}
if [ ! -d "$app_bundle" ] || [ "${app_bundle##*.}" != "app" ]; then
    echo "error: expected an App Bundle: $app_bundle" >&2
    exit 1
fi

required_files='
Contents/Info.plist
Contents/MacOS/tunbridge-desktop
Contents/Library/LaunchServices/com.tunbridge.desktop.helper
Contents/MacOS/tunbridge-helper-macos
Contents/Library/LaunchDaemons/com.tunbridge.desktop.helper.plist
Contents/Resources/tunbridge-helper-policy.json
Contents/Resources/tunbridge-app-policy.json
Contents/Resources/icon.icns
Contents/Resources/tunbridge-engine/mihomo
Contents/Resources/tunbridge-engine/manifest.json'
for relative in $required_files; do
    if [ ! -e "$app_bundle/$relative" ]; then
        echo "error: missing bundle file: $relative" >&2
        exit 1
    fi
done

minimum_version=$(/usr/libexec/PlistBuddy -c 'Print :LSMinimumSystemVersion' \
    "$app_bundle/Contents/Info.plist")
if [ "$minimum_version" != "12.0" ]; then
    echo "error: expected LSMinimumSystemVersion 12.0, observed $minimum_version" >&2
    exit 1
fi

/usr/bin/codesign --verify --deep --strict --verbose=2 "$app_bundle"

mach_o_files='
Contents/MacOS/tunbridge-desktop
Contents/MacOS/tunbridge-helper-macos
Contents/Library/LaunchServices/com.tunbridge.desktop.helper
Contents/Resources/tunbridge-engine/mihomo'
for relative in $mach_o_files; do
    file="$app_bundle/$relative"
    if ! /usr/bin/lipo "$file" -verify_arch "$expected_arch"; then
        echo "error: $relative does not contain expected architecture $expected_arch" >&2
        exit 1
    fi
    if ! /usr/bin/otool -l "$file" |
        /usr/bin/awk '
            $1 == "cmd" && ($2 == "LC_BUILD_VERSION" || $2 == "LC_VERSION_MIN_MACOSX") { in_build = 1; next }
            in_build && ($1 == "minos" || $1 == "version") {
                split($2, components, ".")
                if ((components[1] + 0) > 12) exit 1
                found = 1
                in_build = 0
            }
            END { if (!found) exit 1 }
        '
    then
        echo "error: $relative requires newer than macOS 12" >&2
        exit 1
    fi
done

/usr/bin/python3 - "$app_bundle/Contents/Resources/tunbridge-helper-policy.json" \
    "$app_bundle/Contents/Resources/tunbridge-app-policy.json" <<'PY'
import json
import sys

helper, app = (json.load(open(path, encoding="utf-8")) for path in sys.argv[1:])
if helper.get("schemaVersion") != 1 or helper.get("helperSigningIdentifier") != "com.tunbridge.desktop.helper":
    raise SystemExit("invalid helper policy")
if app.get("schemaVersion") != 1 or app.get("appSigningIdentifier") != "com.tunbridge.desktop":
    raise SystemExit("invalid app policy")
for policy in (helper, app):
    hashes = policy.get("allowedCdhashes")
    if not isinstance(hashes, list) or not 1 <= len(hashes) <= 4:
        raise SystemExit("invalid cdhash allowlist")
    if any(not isinstance(value, str) or len(value) != 40 or value.lower() != value for value in hashes):
        raise SystemExit("invalid cdhash")
print("bundle_policies=ok")
PY

app_identifier=$(/usr/bin/codesign -dv --verbose=4 "$app_bundle/Contents/MacOS/tunbridge-desktop" 2>&1 |
    /usr/bin/awk -F= '/^Identifier=/{print $2; exit}')
helper_identifier=$(/usr/bin/codesign -dv --verbose=4 "$app_bundle/Contents/MacOS/tunbridge-helper-macos" 2>&1 |
    /usr/bin/awk -F= '/^Identifier=/{print $2; exit}')
if [ "$app_identifier" != "com.tunbridge.desktop" ] ||
    [ "$helper_identifier" != "com.tunbridge.desktop.helper" ]; then
    echo "error: role-specific code identifiers are not preserved" >&2
    exit 1
fi

echo "macos_bundle=ok path=$app_bundle arch=$expected_arch minimum_system_version=12.0"
spctl_output=$(/usr/bin/mktemp -t tunbridge-spctl)
trap '/bin/rm -f "$spctl_output"' EXIT HUP INT TERM
if /usr/sbin/spctl --assess --type execute --verbose=2 "$app_bundle" >"$spctl_output" 2>&1; then
    echo "gatekeeper=accepted"
else
    echo "gatekeeper=not_release_candidate"
    exit 0
fi
