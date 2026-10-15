#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_directory/.." && pwd)
desktop_directory=$repository_root/apps/desktop
product_version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "$repository_root/Cargo.toml" | head -n 1)
if [ -z "$product_version" ]; then
    echo "error: workspace product version is missing" >&2
    exit 1
fi

if [ "$(/usr/bin/uname -s)" != "Darwin" ]; then
    echo "error: macOS candidate bundles must be built on macOS" >&2
    exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
    cargo_bin_directory=${CARGO_HOME:-${HOME}/.cargo}/bin
    if [ ! -x "$cargo_bin_directory/cargo" ]; then
        echo "error: cargo is not available in PATH or the standard Cargo bin directory" >&2
        exit 1
    fi
    export PATH="$cargo_bin_directory:$PATH"
fi

export MACOSX_DEPLOYMENT_TARGET=12.0

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

case "$target_triple" in
    aarch64-apple-darwin) target_arch=arm64 ;;
    x86_64-apple-darwin) target_arch=x86_64 ;;
esac

target_output_directory=$repository_root/target/$target_triple/release
app_bundle=$target_output_directory/bundle/macos/TunBridge.app
executable=$app_bundle/Contents/MacOS/tunbridge-desktop
engine_directory=$app_bundle/Contents/Resources/tunbridge-engine
engine_executable=$engine_directory/mihomo
engine_manifest=$engine_directory/manifest.json
helper_directory=$app_bundle/Contents/Library/LaunchServices
helper_executable=$helper_directory/com.tunbridge.desktop.helper
modern_helper=$app_bundle/Contents/MacOS/tunbridge-helper-macos
daemon_plist=$app_bundle/Contents/Library/LaunchDaemons/com.tunbridge.desktop.helper.plist
legacy_daemon_plist=$target_output_directory/tunbridge-helper-legacy-launchd.plist
helper_policy=$app_bundle/Contents/Resources/tunbridge-helper-policy.json
app_policy=$app_bundle/Contents/Resources/tunbridge-app-policy.json
internal_installer=${TUNBRIDGE_MACOS_INTERNAL_INSTALLER:-1}
case "$internal_installer" in
    0|1) ;;
    *) echo "error: TUNBRIDGE_MACOS_INTERNAL_INSTALLER must be 0 or 1" >&2; exit 1 ;;
esac

engine_source=$(node "$repository_root/scripts/fetch-macos-mihomo.mjs" fetch "$target_triple")

cd "$desktop_directory"
if [ "$internal_installer" = 1 ]; then
    npm run tauri -- build --target "$target_triple" --bundles app \
        --features macos-development-installer \
        --config '{"bundle":{"active":true,"targets":["app"]}}'
else
    npm run tauri -- build --target "$target_triple" --bundles app \
        --config '{"bundle":{"active":true,"targets":["app"]}}'
fi

/bin/mkdir -p "$helper_directory" "$(/usr/bin/dirname "$daemon_plist")" \
    "$app_bundle/Contents/Resources"

if [ "$internal_installer" = 1 ]; then
    team_id=adhoc
    helper_requirement='identifier "com.tunbridge.desktop.helper"'
    authorized_client_requirement='identifier "com.tunbridge.desktop"'
else
    team_id=${TUNBRIDGE_TEAM_ID:-ABCDE12345}
    case "$team_id" in
        ??????????)
            if ! printf '%s' "$team_id" | /usr/bin/grep -Eq '^[A-Z0-9]{10}$'; then
                echo "error: TUNBRIDGE_TEAM_ID must be exactly 10 uppercase letters/digits" >&2
                exit 1
            fi
            ;;
        *)
            echo "error: TUNBRIDGE_TEAM_ID must be exactly 10 uppercase letters/digits" >&2
            exit 1
            ;;
    esac
    helper_requirement="anchor apple generic and identifier \"com.tunbridge.desktop.helper\" and certificate leaf[subject.OU] = \"$team_id\" and flags runtime"
    authorized_client_requirement="anchor apple generic and identifier \"com.tunbridge.desktop\" and certificate leaf[subject.OU] = \"$team_id\" and flags runtime"
fi

/usr/bin/plutil -convert xml1 -o "$daemon_plist" -- - <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.tunbridge.desktop.helper</string>
  <key>BundleProgram</key>
  <string>Contents/MacOS/tunbridge-helper-macos</string>
  <key>MachServices</key>
  <dict>
    <key>com.tunbridge.desktop.helper</key>
    <true/>
  </dict>
  <key>RunAtLoad</key>
  <false/>
  <key>ProcessType</key>
  <string>Interactive</string>
</dict>
</plist>
PLIST

# SMJobBless extracts this plist into /Library/LaunchDaemons and supplies the
# fixed Program/ProgramArguments itself.  Do not embed BundleProgram here: it
# belongs only to the macOS 13+ bundle-relative SMAppService daemon plist
# above, and macOS 26 rejects the mixed legacy/modern launchd configuration.
/usr/bin/plutil -convert xml1 -o "$legacy_daemon_plist" -- - <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.tunbridge.desktop.helper</string>
  <key>MachServices</key>
  <dict>
    <key>com.tunbridge.desktop.helper</key>
    <true/>
  </dict>
  <key>RunAtLoad</key>
  <false/>
</dict>
</plist>
PLIST

helper_info=$target_output_directory/tunbridge-helper-info.plist
/usr/bin/plutil -convert xml1 -o "$helper_info" -- - <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.tunbridge.desktop.helper</string>
  <key>CFBundleExecutable</key>
  <string>tunbridge-helper-macos</string>
  <key>CFBundlePackageType</key>
  <string>XPC!</string>
  <key>CFBundleVersion</key>
  <string>$product_version</string>
  <key>XPCService</key>
  <dict>
    <key>ServiceType</key>
    <string>Application</string>
    <key>RunLoopType</key>
    <string>dispatch_main</string>
  </dict>
  <key>SMAuthorizedClients</key>
  <array>
    <string>$authorized_client_requirement</string>
  </array>
</dict>
</plist>
PLIST

/bin/mkdir -p "$engine_directory"
/bin/cp "$engine_source" "$engine_executable"
/bin/chmod 0755 "$engine_executable"

# Sign nested code before generating the runtime integrity manifest. Signing a
# Mach-O changes its bytes, so the helper must validate the sealed payload and
# not the unsigned upstream digest.
/usr/bin/codesign --force --sign - --options runtime "$engine_executable"
node "$repository_root/scripts/fetch-macos-mihomo.mjs" manifest \
    "$target_triple" "$engine_executable" "$engine_manifest"

# The internal-installer helper provisions only the exact signed engine
# bundled here, so sign it first and build its digest into the helper.
pinned_engine_sha256=$(/usr/bin/shasum -a 256 "$engine_executable" | /usr/bin/awk '{print $1}')
case "$pinned_engine_sha256" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
    *) echo "error: could not hash the signed bundled engine" >&2; exit 1 ;;
esac

saved_rustflags=${RUSTFLAGS-}
if [ "$internal_installer" = 1 ]; then
    export RUSTFLAGS="$saved_rustflags -C link-arg=-Wl,-sectcreate,__TEXT,__info_plist,$helper_info -C link-arg=-Wl,-sectcreate,__TEXT,__launchd_plist,$legacy_daemon_plist"
    helper_features=macos-helper-scaffold,macos-xpc-listener,macos-development-bootstrap
else
    export RUSTFLAGS="$saved_rustflags -C link-arg=-Wl,-sectcreate,__TEXT,__info_plist,$helper_info -C link-arg=-Wl,-sectcreate,__TEXT,__launchd_plist,$legacy_daemon_plist"
    helper_features=macos-helper-scaffold,macos-xpc-listener
fi

# The candidate carries both Monterey and modern helper slots so recursive
# bundle inspection exercises the same layout as a release.  Both slots point
# at one production helper implementation; the OS-specific registration API
# is selected later by the installer.  This script intentionally builds an
# ad-hoc candidate and never installs either helper.
TUNBRIDGE_PINNED_ENGINE_SHA256=$pinned_engine_sha256 \
cargo build --release --package tunbridge-service-macos \
    --bin tunbridge-helper-macos \
    --features "$helper_features" \
    --target "$target_triple"
if [ -n "$saved_rustflags" ]; then export RUSTFLAGS="$saved_rustflags"; else unset RUSTFLAGS; fi
helper_source=$repository_root/target/$target_triple/release/tunbridge-helper-macos
if [ ! -x "$helper_source" ]; then
    echo "error: helper build did not produce $helper_source" >&2
    exit 1
fi

/bin/cp "$helper_source" "$helper_executable"
/bin/cp "$helper_source" "$modern_helper"
/bin/chmod 0755 "$helper_executable" "$modern_helper"


/usr/bin/codesign --force --sign - --options runtime \
    --identifier com.tunbridge.desktop.helper "$helper_executable"
/usr/bin/codesign --force --sign - --options runtime \
    --identifier com.tunbridge.desktop.helper "$modern_helper"

# Intel linker output can be unsigned. Seal the Desktop executable before
# extracting its code hash, just as we already seal the nested helper.
/usr/bin/codesign --force --sign - --options runtime \
    --identifier com.tunbridge.desktop "$executable"

app_cdhash=$(/usr/bin/codesign -d --verbose=4 "$executable" 2>&1 |
    /usr/bin/awk -F= '/^CDHash=/{print tolower($2); exit}')
helper_cdhash=$(/usr/bin/codesign -d --verbose=4 "$helper_executable" 2>&1 |
    /usr/bin/awk -F= '/^CDHash=/{print tolower($2); exit}')
if [ "$internal_installer" = 1 ] &&
    ! printf '%s\n%s\n' "$app_cdhash" "$helper_cdhash" |
        /usr/bin/awk 'length($0) != 40 || $0 !~ /^[0-9a-f]+$/ { invalid = 1 } END { exit invalid }'
then
    echo "error: ad-hoc candidate code hashes are unavailable" >&2
    exit 1
fi

/usr/bin/plutil -replace SMPrivilegedExecutables -xml \
    "<dict><key>com.tunbridge.desktop.helper</key><string>$helper_requirement</string></dict>" \
    "$app_bundle/Contents/Info.plist" 2>/dev/null || \
    /usr/bin/plutil -insert SMPrivilegedExecutables -xml \
        "<dict><key>com.tunbridge.desktop.helper</key><string>$helper_requirement</string></dict>" \
        "$app_bundle/Contents/Info.plist"

if [ "$internal_installer" = 1 ]; then
    /usr/bin/printf '%s\n' \
        '{"schemaVersion":1,"teamId":"adhoc","helperSigningIdentifier":"com.tunbridge.desktop.helper","allowedCdhashes":["'"$helper_cdhash"'"]}' \
        > "$helper_policy"
    /usr/bin/printf '%s\n' \
        '{"schemaVersion":1,"teamId":"adhoc","appSigningIdentifier":"com.tunbridge.desktop","allowedCdhashes":["'"$app_cdhash"'"]}' \
        > "$app_policy"
else
    /usr/bin/printf '%s\n' \
        '{"schemaVersion":1,"teamId":"'"$team_id"'","helperSigningIdentifier":"com.tunbridge.desktop.helper","allowedCdhashes":["1111111111111111111111111111111111111111"]}' \
        > "$helper_policy"
    /usr/bin/printf '%s\n' \
        '{"schemaVersion":1,"teamId":"'"$team_id"'","appSigningIdentifier":"com.tunbridge.desktop","allowedCdhashes":["1111111111111111111111111111111111111111"]}' \
        > "$app_policy"
fi

# This stage deliberately creates an isolated-test candidate. A release build
# must sign each nested component inside-out with Developer ID before
# notarization; ad-hoc signing here must never be presented as release evidence.
# Nested executables were already signed with their role-specific identifiers;
# signing the outer bundle without --deep preserves those nested identities.
/usr/bin/codesign --force --sign - --options runtime \
    --identifier com.tunbridge.desktop "$app_bundle"
/usr/bin/codesign --verify --deep --strict --verbose=2 "$app_bundle"

if ! /usr/bin/lipo "$engine_executable" -verify_arch "$target_arch"; then
    echo "error: bundled engine architecture does not match candidate" >&2
    exit 1
fi

if ! /usr/bin/otool -l "$engine_executable" |
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
    echo "error: bundled engine requires a macOS version newer than 12" >&2
    exit 1
fi

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

echo "macos_candidate=ok path=$app_bundle signing=ad-hoc minimum_system_version=12.0 engine=$target_triple"
