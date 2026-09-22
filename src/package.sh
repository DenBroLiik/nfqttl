#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

BIN="libs/arm64-v8a/nfqttl"
[ -x "$BIN" ] || {
    echo "error: missing executable $BIN" >&2
    echo "run ./src/build.sh first" >&2
    exit 1
}

# Re-validate the binary even when package.sh is invoked directly.
if command -v readelf >/dev/null 2>&1; then
    MACHINE=$(LC_ALL=C readelf -h "$BIN" | sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p')
    case "$MACHINE" in
        AArch64|*AArch64*) : ;;
        *) echo "error: package binary is not AArch64: ${MACHINE:-unknown}" >&2; exit 1 ;;
    esac
    if LC_ALL=C readelf -l "$BIN" | grep -q 'Requesting program interpreter'; then
        echo "error: package binary is dynamically linked; static binary required" >&2
        exit 1
    fi
fi

VERSION=$(sed -n 's/^version=//p' module.prop | head -n1)
[ -n "$VERSION" ] || VERSION="v4.0.0-rust"

OUT=${1:-"dist/nfqttl-${VERSION}.zip"}
mkdir -p "$(dirname "$OUT")"
OUT=$(readlink -f "$OUT")
rm -f "$OUT" "$OUT.sha256"

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT INT TERM

# Runtime/install payload only. Keep module.prop at ZIP root.
for f in module.prop config.conf customize.sh service.sh control.sh diagnose.sh uninstall.sh README_RU.md DEV.md LICENSE; do
    [ -e "$f" ] || { echo "error: missing required payload: $f" >&2; exit 1; }
    cp -a "$f" "$STAGE/"
done

cp -a META-INF "$STAGE/"
cp -a kernel "$STAGE/"
mkdir -p "$STAGE/libs/arm64-v8a"
cp -a "$BIN" "$STAGE/libs/arm64-v8a/nfqttl"

chmod 0755 \
    "$STAGE/customize.sh" \
    "$STAGE/service.sh" \
    "$STAGE/control.sh" \
    "$STAGE/diagnose.sh" \
    "$STAGE/uninstall.sh" \
    "$STAGE/libs/arm64-v8a/nfqttl"

(
    cd "$STAGE"
    zip -qr9 "$OUT" .
)

# Validate the archive so an incomplete module can never be reported as built.
LIST=$(unzip -Z1 "$OUT")
for required in \
    module.prop \
    customize.sh \
    service.sh \
    control.sh \
    diagnose.sh \
    uninstall.sh \
    config.conf \
    libs/arm64-v8a/nfqttl; do
    printf '%s\n' "$LIST" | grep -Fxq "$required" || {
        echo "error: packaged ZIP is missing $required" >&2
        exit 1
    }
done

# Reject a common packaging mistake: one enclosing top-level project directory.
FIRST=$(printf '%s\n' "$LIST" | sed -n '1p')
case "$FIRST" in
    */module.prop) echo "error: module.prop is not at ZIP root" >&2; exit 1 ;;
esac

sha256sum "$OUT" | tee "$OUT.sha256"
echo "install ZIP: $OUT"
