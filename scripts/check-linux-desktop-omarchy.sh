#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_directory/.." && pwd)
packaging_root="$repository_root/platforms/linux/packaging/arch"

sh -n "$packaging_root/tunbridge-desktop.install"
sh -n "$packaging_root/tunbridge-package-guard"
bash -n "$packaging_root/PKGBUILD.in"
desktop-file-validate "$packaging_root/tunbridge.desktop"

grep -F "pkgname=tunbridge-desktop" "$packaging_root/PKGBUILD.in" >/dev/null
for dependency in gtk3 libayatana-appindicator libsecret iproute2 nftables polkit systemd webkit2gtk-4.1 xdg-utils; do
    grep -F "'$dependency'" "$packaging_root/PKGBUILD.in" >/dev/null
done
grep -F "options=('!debug' '!strip')" "$packaging_root/PKGBUILD.in" >/dev/null
grep -F '"package_kind": "pacman"' "$packaging_root/linux-service-layout.json" >/dev/null
grep -F 'omarchy-package' "$repository_root/apps/desktop/src-tauri/src/main.rs" >/dev/null
grep -F 'WEBKIT_DISABLE_DMABUF_RENDERER' \
    "$repository_root/apps/desktop/src-tauri/src/main.rs" >/dev/null
grep -F '/proc/[0-9]*/exe' "$packaging_root/tunbridge-desktop.install" >/dev/null
grep -F '/proc/[0-9]*/exe' "$packaging_root/tunbridge-package-guard" >/dev/null
grep -F 'Operation = Upgrade' \
    "$packaging_root/tunbridge-desktop-upgrade-guard.hook" >/dev/null
grep -F 'Target = tunbridge-desktop' \
    "$packaging_root/tunbridge-desktop-upgrade-guard.hook" >/dev/null
grep -F 'When = PreTransaction' \
    "$packaging_root/tunbridge-desktop-upgrade-guard.hook" >/dev/null
grep -F 'Exec = /usr/libexec/tunbridge/tunbridge-package-guard' \
    "$packaging_root/tunbridge-desktop-upgrade-guard.hook" >/dev/null
grep -Fx 'AbortOnFail' \
    "$packaging_root/tunbridge-desktop-upgrade-guard.hook" >/dev/null
grep -F 'systemctl --system restart tunbridge.service' \
    "$packaging_root/tunbridge-desktop.install" >/dev/null
grep -F '/proc/$service_pid/exe' "$packaging_root/tunbridge-desktop.install" >/dev/null
grep -F '[ "$service_identity_attempts" -lt 50 ]' \
    "$packaging_root/tunbridge-desktop.install" >/dev/null
if grep -F 'systemctl --system restart tunbridge.service >/dev/null || true' \
    "$packaging_root/tunbridge-desktop.install" >/dev/null; then
    echo "Omarchy post-upgrade must fail closed when service restart fails." >&2
    exit 1
fi
if grep -E 'SUDO_USER|logname|\$USER|adduser|addgroup|groupadd|usermod|gpasswd' \
    "$packaging_root/tunbridge-desktop.install" >/dev/null; then
    echo "Omarchy package hooks must not guess or mutate a desktop user." >&2
    exit 1
fi

echo "linux_desktop_omarchy_contract=ok"
