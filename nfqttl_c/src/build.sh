#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
: "${ZIG:=zig}"
for spec in arm64-v8a:aarch64-linux-musl x86_64:x86_64-linux-musl armeabi-v7a:arm-linux-musleabihf x86:x86-linux-musl; do
    abi=${spec%%:*}; target=${spec#*:}
    mkdir -p "libs/$abi"
    "$ZIG" cc -target "$target" -static -O2 -Wall -Wextra -Werror -s \
        src/nfqttl-lite.c -o "libs/$abi/nfqttl-lite"
done
