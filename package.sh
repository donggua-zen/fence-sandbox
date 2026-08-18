#!/bin/bash
# Locally package the built binary for the current platform into ./dist,
# mirroring the archive naming used by the CI Release workflow.
#
# Usage: bash package.sh   (after running build_project.sh / cmake build)
set -euo pipefail

cd "$(dirname "$0")"

BIN_DIR="build/bin"
if [ ! -d "$BIN_DIR" ]; then
    echo "ERROR: $BIN_DIR not found. Run './build_project.sh' (or cmake build) first." >&2
    exit 1
fi

case "$(uname -s)" in
    Linux*)  OS="linux"   ; BIN="sandbox" ; EXT="tar.gz" ;;
    Darwin*) OS="macos"   ; BIN="sandbox" ; EXT="tar.gz" ;;
    MINGW*|MSYS*|CYGWIN*) OS="windows" ; BIN="sandbox.exe" ; EXT="zip" ;;
    *) echo "ERROR: unsupported platform: $(uname -s)" >&2 ; exit 1 ;;
esac

case "$(uname -m)" in
    arm64|aarch64) ARCH="arm64" ;;
    x86_64|amd64)  ARCH="x64"   ;;
    *) ARCH="$(uname -m)" ;;
esac

if [ ! -f "$BIN_DIR/$BIN" ]; then
    echo "ERROR: $BIN_DIR/$BIN not found." >&2
    exit 1
fi

mkdir -p dist
OUT="dist/fence-sandbox-${OS}-${ARCH}.${EXT}"
rm -f "$OUT"

if [ "$EXT" = "zip" ]; then
    tar -a -c -f "$OUT" -C "$BIN_DIR" "$BIN"
else
    tar -czf "$OUT" -C "$BIN_DIR" "$BIN"
fi

echo "Packaged: $OUT"
ls -la "$OUT"
