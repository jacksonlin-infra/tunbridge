#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
version=v1.19.30
asset=mihomo-linux-amd64-compatible-v1.19.30.gz
expected_gzip_size=18899951
expected_gzip_sha256=db214c7a2517e63c150d123178d16d102e03a241ccdae4e5e07ffbe9cf56c6f9
expected_binary_size=50999422
expected_binary_sha256=8ad44e28fe72be4640254b96741b677f4074991b99186cc4486a1c28ded02b1a
download_root="$repository_root/target/linux-engine"
archive="$download_root/$asset"
binary="$repository_root/target/release/mihomo"
url="https://github.com/MetaCubeX/mihomo/releases/download/$version/$asset"

mkdir -p "$download_root" "$repository_root/target/release"
if [ -f "$binary" ] &&
    [ "$(wc -c <"$binary" | tr -d ' ')" = "$expected_binary_size" ] &&
    [ "$(sha256sum "$binary" | cut -d' ' -f1)" = "$expected_binary_sha256" ]; then
    chmod 0755 "$binary"
    printf 'mihomo=%s\n' "$binary"
    printf 'sha256=%s\n' "$expected_binary_sha256"
    exit 0
fi
if [ ! -f "$archive" ] ||
    [ "$(wc -c <"$archive" | tr -d ' ')" != "$expected_gzip_size" ] ||
    [ "$(sha256sum "$archive" | cut -d' ' -f1)" != "$expected_gzip_sha256" ]; then
    temporary="$archive.download"
    rm -f -- "$temporary"
    curl -fL --retry 3 --output "$temporary" "$url"
    test "$(wc -c <"$temporary" | tr -d ' ')" = "$expected_gzip_size"
    test "$(sha256sum "$temporary" | cut -d' ' -f1)" = "$expected_gzip_sha256"
    mv -f -- "$temporary" "$archive"
fi

temporary_binary="$binary.download"
rm -f -- "$temporary_binary"
gzip -dc "$archive" >"$temporary_binary"
test "$(wc -c <"$temporary_binary" | tr -d ' ')" = "$expected_binary_size"
test "$(sha256sum "$temporary_binary" | cut -d' ' -f1)" = "$expected_binary_sha256"
chmod 0755 "$temporary_binary"
mv -f -- "$temporary_binary" "$binary"

printf 'mihomo=%s\n' "$binary"
printf 'sha256=%s\n' "$expected_binary_sha256"
