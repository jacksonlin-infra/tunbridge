#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
    echo "usage: verify-linux-desktop-deb.sh <package.deb>" >&2
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

dpkg-deb --extract "$package_path" "$temporary_root/root"
dpkg-deb --control "$package_path" "$temporary_root/control"

[ "$(dpkg-deb --field "$package_path" Architecture)" = "amd64" ]
[ "$(dpkg-deb --field "$package_path" Version)" = "$product_version" ]
dpkg-deb --field "$package_path" Depends | grep -F "libwebkit2gtk-4.1-0" >/dev/null
dpkg-deb --field "$package_path" Depends | grep -F "libgtk-3-0" >/dev/null
dpkg-deb --field "$package_path" Depends | grep -F "libayatana-appindicator3-1" >/dev/null
dpkg-deb --field "$package_path" Depends | grep -F "libsecret-tools" >/dev/null
dpkg-deb --field "$package_path" Depends | grep -F "iproute2" >/dev/null
dpkg-deb --field "$package_path" Depends | grep -F "nftables" >/dev/null
dpkg-deb --field "$package_path" Depends | grep -F "pkexec" >/dev/null
dpkg-deb --field "$package_path" Depends | grep -F "systemd" >/dev/null

test -x "$temporary_root/root/usr/bin/tunbridge-desktop"
test -x "$temporary_root/root/usr/libexec/tunbridge/tunbridge-service-linux"
test -x "$temporary_root/root/usr/libexec/tunbridge/tunbridge-maintenance-linux"
test -x "$temporary_root/root/usr/libexec/tunbridge/mihomo"
test -f "$temporary_root/root/usr/share/tunbridge/engine-manifest.json"
cmp "$repository_root/platforms/linux/packaging/deb/engine-manifest.json" \
    "$temporary_root/root/usr/share/tunbridge/engine-manifest.json"
expected_engine_size=$(sed -n 's/.*"binarySize": \([0-9][0-9]*\).*/\1/p' \
    "$repository_root/platforms/linux/packaging/deb/engine-manifest.json")
expected_engine_sha256=$(sed -n 's/.*"binarySha256": "\([0-9a-f][0-9a-f]*\)".*/\1/p' \
    "$repository_root/platforms/linux/packaging/deb/engine-manifest.json")
[ "$(stat -c %s "$temporary_root/root/usr/libexec/tunbridge/mihomo")" = "$expected_engine_size" ]
[ "$(sha256sum "$temporary_root/root/usr/libexec/tunbridge/mihomo" | cut -d' ' -f1)" = \
    "$expected_engine_sha256" ]
test -f "$temporary_root/root/usr/lib/systemd/system/tunbridge.service"
test -f "$temporary_root/root/usr/share/tunbridge/linux-service-layout.json"

[ "$(stat -c %a "$temporary_root/root/usr/libexec/tunbridge/tunbridge-service-linux")" = "755" ]
[ "$(stat -c %a "$temporary_root/root/usr/libexec/tunbridge/tunbridge-maintenance-linux")" = "755" ]
[ "$(stat -c %a "$temporary_root/root/usr/share/tunbridge/engine-manifest.json")" = "644" ]
[ "$(stat -c %a "$temporary_root/root/usr/lib/systemd/system/tunbridge.service")" = "644" ]
[ "$(stat -c %a "$temporary_root/root/usr/share/tunbridge/linux-service-layout.json")" = "644" ]

for script in preinst postinst prerm postrm; do
    test -x "$temporary_root/control/$script"
    dash -n "$temporary_root/control/$script"
    if grep -E 'SUDO_USER|logname|\\$USER|adduser|addgroup|groupadd|usermod|gpasswd|delgroup' \
        "$temporary_root/control/$script" >/dev/null; then
        echo "$script contains a forbidden user or group mutation." >&2
        exit 1
    fi
done

grep -F '/proc/[0-9]*/exe' "$temporary_root/control/preinst" >/dev/null
grep -F 'Quit it from the tray' "$temporary_root/control/preinst" >/dev/null
grep -F 'deb-systemd-invoke restart tunbridge.service' \
    "$temporary_root/control/postinst" >/dev/null
grep -F 'is-active --quiet tunbridge.service' "$temporary_root/control/postinst" >/dev/null
grep -F '/proc/$service_pid/exe' "$temporary_root/control/postinst" >/dev/null
grep -F 'service_identity_attempts=0' "$temporary_root/control/postinst" >/dev/null
grep -F '[ "$service_identity_attempts" -lt 50 ]' \
    "$temporary_root/control/postinst" >/dev/null
grep -F 'sleep 0.1' "$temporary_root/control/postinst" >/dev/null
grep -F '[ "$service_identity_verified" != true ]' \
    "$temporary_root/control/postinst" >/dev/null
if grep -F 'deb-systemd-invoke restart tunbridge.service >/dev/null || true' \
    "$temporary_root/control/postinst" >/dev/null; then
    echo "postinst must fail closed when an upgraded service cannot restart." >&2
    exit 1
fi

grep -F 'remove_owned_file /var/lib/tunbridge/cache.db' "$temporary_root/control/postrm" >/dev/null
grep -F 'remove_owned_file /var/lib/tunbridge/maintenance.lock' "$temporary_root/control/postrm" >/dev/null
grep -F 'remove_owned_file /usr/libexec/tunbridge/mihomo.rollback' "$temporary_root/control/postrm" >/dev/null
grep -F 'remove_owned_file /usr/share/tunbridge/engine-manifest.json.rollback' "$temporary_root/control/postrm" >/dev/null

grep -F '"service_capabilities": [' "$temporary_root/root/usr/share/tunbridge/linux-service-layout.json" >/dev/null
grep -F '"status"' "$temporary_root/root/usr/share/tunbridge/linux-service-layout.json" >/dev/null
grep -F '"membership_policy": "not-required-kernel-peer-authorization"' "$temporary_root/root/usr/share/tunbridge/linux-service-layout.json" >/dev/null
grep -F '"socket_mode": "0666"' "$temporary_root/root/usr/share/tunbridge/linux-service-layout.json" >/dev/null
grep -F 'Group=root' "$temporary_root/root/usr/lib/systemd/system/tunbridge.service" >/dev/null
grep -F 'CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE' \
    "$temporary_root/root/usr/lib/systemd/system/tunbridge.service" >/dev/null
grep -F 'AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE' \
    "$temporary_root/root/usr/lib/systemd/system/tunbridge.service" >/dev/null
grep -F 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' \
    "$temporary_root/root/usr/lib/systemd/system/tunbridge.service" >/dev/null

desktop_file=$(find "$temporary_root/root/usr/share/applications" -maxdepth 1 -type f -name '*.desktop' -print -quit)
test -n "$desktop_file"
desktop-file-validate "$desktop_file"

echo "linux_desktop_deb=ok"
