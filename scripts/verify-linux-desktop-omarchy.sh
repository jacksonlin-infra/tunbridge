#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
    echo "usage: verify-linux-desktop-omarchy.sh <package.pkg.tar.zst>" >&2
    exit 2
fi
package_path=$(CDPATH= cd -- "$(dirname -- "$1")" && pwd)/$(basename "$1")
script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_directory/.." && pwd)
product_version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "$repository_root/Cargo.toml" | head -n 1)
temporary_root=$(mktemp -d)
cleanup() {
    rm -rf -- "$temporary_root"
}
trap cleanup EXIT HUP INT TERM

bsdtar -xf "$package_path" -C "$temporary_root"
package_info=$(bsdtar -xOf "$package_path" .PKGINFO)
printf '%s\n' "$package_info" | grep -Fx "pkgname = tunbridge-desktop" >/dev/null
printf '%s\n' "$package_info" | grep -Fx "pkgver = $product_version-1" >/dev/null
printf '%s\n' "$package_info" | grep -Fx "arch = x86_64" >/dev/null
for dependency in gtk3 libayatana-appindicator libsecret iproute2 nftables polkit systemd webkit2gtk-4.1 xdg-utils; do
    printf '%s\n' "$package_info" | grep -Fx "depend = $dependency" >/dev/null
done

test -x "$temporary_root/usr/bin/tunbridge-desktop"
test -x "$temporary_root/usr/libexec/tunbridge/tunbridge-service-linux"
test -x "$temporary_root/usr/libexec/tunbridge/tunbridge-maintenance-linux"
test -x "$temporary_root/usr/libexec/tunbridge/tunbridge-package-guard"
test -x "$temporary_root/usr/libexec/tunbridge/mihomo"
test -f "$temporary_root/usr/lib/systemd/system/tunbridge.service"
test -f "$temporary_root/usr/share/tunbridge/engine-manifest.json"
test -f "$temporary_root/usr/share/tunbridge/linux-service-layout.json"
test -f "$temporary_root/usr/share/applications/tunbridge.desktop"
test -f "$temporary_root/usr/share/libalpm/hooks/tunbridge-desktop-upgrade-guard.hook"
test -f "$temporary_root/.INSTALL"
strings "$temporary_root/usr/bin/tunbridge-desktop" | \
    grep -F 'WEBKIT_DISABLE_DMABUF_RENDERER' >/dev/null

cmp "$repository_root/platforms/linux/packaging/deb/engine-manifest.json" \
    "$temporary_root/usr/share/tunbridge/engine-manifest.json"
expected_engine_size=$(sed -n 's/.*"binarySize": \([0-9][0-9]*\).*/\1/p' \
    "$repository_root/platforms/linux/packaging/deb/engine-manifest.json")
expected_engine_sha256=$(sed -n 's/.*"binarySha256": "\([0-9a-f][0-9a-f]*\)".*/\1/p' \
    "$repository_root/platforms/linux/packaging/deb/engine-manifest.json")
[ "$(stat -c %s "$temporary_root/usr/libexec/tunbridge/mihomo")" = "$expected_engine_size" ]
[ "$(sha256sum "$temporary_root/usr/libexec/tunbridge/mihomo" | cut -d' ' -f1)" = \
    "$expected_engine_sha256" ]
[ "$(stat -c %a "$temporary_root/usr/libexec/tunbridge/tunbridge-service-linux")" = 755 ]
[ "$(stat -c %a "$temporary_root/usr/lib/systemd/system/tunbridge.service")" = 644 ]
grep -F '"package_kind": "pacman"' \
    "$temporary_root/usr/share/tunbridge/linux-service-layout.json" >/dev/null
grep -F 'CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE' \
    "$temporary_root/usr/lib/systemd/system/tunbridge.service" >/dev/null
grep -F 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' \
    "$temporary_root/usr/lib/systemd/system/tunbridge.service" >/dev/null
grep -F '/proc/[0-9]*/exe' "$temporary_root/.INSTALL" >/dev/null
grep -F '/proc/[0-9]*/exe' \
    "$temporary_root/usr/libexec/tunbridge/tunbridge-package-guard" >/dev/null
grep -F 'When = PreTransaction' \
    "$temporary_root/usr/share/libalpm/hooks/tunbridge-desktop-upgrade-guard.hook" >/dev/null
grep -F 'Exec = /usr/libexec/tunbridge/tunbridge-package-guard' \
    "$temporary_root/usr/share/libalpm/hooks/tunbridge-desktop-upgrade-guard.hook" >/dev/null
grep -Fx 'AbortOnFail' \
    "$temporary_root/usr/share/libalpm/hooks/tunbridge-desktop-upgrade-guard.hook" >/dev/null
grep -F 'systemctl --system restart tunbridge.service' "$temporary_root/.INSTALL" >/dev/null
grep -F '/proc/$service_pid/exe' "$temporary_root/.INSTALL" >/dev/null
desktop-file-validate "$temporary_root/usr/share/applications/tunbridge.desktop"
for binary in \
    "$temporary_root/usr/bin/tunbridge-desktop" \
    "$temporary_root/usr/libexec/tunbridge/tunbridge-service-linux" \
    "$temporary_root/usr/libexec/tunbridge/tunbridge-maintenance-linux" \
    "$temporary_root/usr/libexec/tunbridge/tunbridge-package-guard" \
    "$temporary_root/usr/libexec/tunbridge/mihomo"; do
    case "$binary" in
        *tunbridge-package-guard) continue ;;
    esac
    readelf -h "$binary" | grep -F 'Class:                             ELF64' >/dev/null
    readelf -h "$binary" | grep -F 'Machine:                           Advanced Micro Devices X86-64' >/dev/null
done

echo "linux_desktop_omarchy_package=ok"
