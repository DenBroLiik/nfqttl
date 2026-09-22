#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

: "${CARGO:=cargo}"
: "${RUSTC:=rustc}"
: "${RUSTUP:=rustup}"

TARGET=aarch64-unknown-linux-musl

"$RUSTUP" target add "$TARGET" >/dev/null

SYSROOT=$("$RUSTC" --print sysroot)
HOST=$("$RUSTC" -vV | sed -n 's/^host: //p')
RUST_LLD="$SYSROOT/lib/rustlib/$HOST/bin/rust-lld"

if [ ! -x "$RUST_LLD" ]; then
    echo "rust-lld was not found at: $RUST_LLD" >&2
    echo "Active toolchain: $SYSROOT" >&2
    exit 1
fi

# aarch64-unknown-linux-musl ships its own musl CRT/libc objects.
# Use Rust's bundled LLD directly so no external compiler driver can add a
# second crt1.o (_start), which would cause duplicate-symbol linker errors.
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$RUST_LLD" \
RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-C link-self-contained=yes -C linker-flavor=ld.lld" \
    "$CARGO" build --release --target "$TARGET"

OUT="target/$TARGET/release/nfqttl"
DEST="libs/arm64-v8a/nfqttl"

mkdir -p "$(dirname "$DEST")"
cp -f "$OUT" "$DEST"
chmod 0755 "$DEST"

if command -v file >/dev/null 2>&1; then
    file "$DEST"
fi

if command -v readelf >/dev/null 2>&1; then
    MACHINE=$(LC_ALL=C readelf -h "$DEST" | sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p')
    case "$MACHINE" in
        AArch64|*AArch64*) : ;;
        *) echo "unexpected ELF machine: ${MACHINE:-unknown}" >&2; exit 1 ;;
    esac

    if LC_ALL=C readelf -l "$DEST" | grep -q 'Requesting program interpreter'; then
        echo "error: produced binary is dynamically linked; static binary required" >&2
        exit 1
    fi
fi

if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$DEST"
fi

# Build the installable KernelSU/Magisk ZIP only after the ARM64 binary passed
# architecture/static-link validation above.
"./src/package.sh"
