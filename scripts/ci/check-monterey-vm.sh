#!/bin/sh
set -eu

expected_version=12.7.6
observed_version=$(/usr/bin/sw_vers -productVersion)
observed_build=$(/usr/bin/sw_vers -buildVersion)
observed_arch=$(/usr/bin/uname -m)

if [ "$observed_version" != "$expected_version" ]; then
    echo "error: expected macOS $expected_version, observed $observed_version ($observed_build)" >&2
    exit 1
fi

case "$observed_arch" in
    arm64|x86_64) ;;
    *)
        echo "error: unsupported Monterey architecture: $observed_arch" >&2
        exit 1
        ;;
esac

if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo is not available on PATH" >&2
    exit 1
fi

export MACOSX_DEPLOYMENT_TARGET=12.0

echo "monterey_version=$observed_version build=$observed_build arch=$observed_arch"
cargo test -p tunbridge-setup-macos --offline
cargo test -p tunbridge-service-macos --all-features --offline
cargo test -p tunbridge-desktop --offline

if [ "${TUNBRIDGE_TEST_APP_BUNDLE:-}" != "" ]; then
    app_bundle=$TUNBRIDGE_TEST_APP_BUNDLE
    executable=$app_bundle/Contents/MacOS/tunbridge-desktop
    if [ ! -x "$executable" ]; then
        echo "error: missing candidate executable: $executable" >&2
        exit 1
    fi
    /usr/bin/codesign --verify --deep --strict --verbose=2 "$app_bundle"
    minimum_version=$(/usr/libexec/PlistBuddy \
        -c 'Print :LSMinimumSystemVersion' "$app_bundle/Contents/Info.plist")
    if [ "$minimum_version" != "12.0" ]; then
        echo "error: expected LSMinimumSystemVersion 12.0, observed $minimum_version" >&2
        exit 1
    fi
    if ! /usr/bin/otool -l "$executable" |
        /usr/bin/awk '
            $1 == "cmd" && $2 == "LC_BUILD_VERSION" { in_build = 1; next }
            in_build && $1 == "minos" {
                if ($2 != "12.0") exit 1
                found = 1
                in_build = 0
            }
            END { if (!found) exit 1 }
        '
    then
        echo "error: candidate main executable does not declare minos 12.0" >&2
        exit 1
    fi
    echo "candidate_bundle=ok path=$app_bundle minimum_system_version=12.0"
fi

echo "monterey_vm_check=ok"
