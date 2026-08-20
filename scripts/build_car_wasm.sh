#!/bin/sh
set -eu

CAR_PARSER_REVISION="dee176b984598efbdf02ed2834aeb7cd01386046"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
BUILD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/openbundle-car-parser.XXXXXX")
trap 'rm -rf "$BUILD_DIR"' EXIT HUP INT TERM

command -v git >/dev/null 2>&1 || {
  echo "build_car_wasm.sh: git is required" >&2
  exit 1
}
command -v wasm-pack >/dev/null 2>&1 || {
  echo "build_car_wasm.sh: wasm-pack is required" >&2
  exit 1
}

git clone --quiet https://github.com/skytoup/car-parser.git "$BUILD_DIR/car-parser"
git -C "$BUILD_DIR/car-parser" checkout --quiet "$CAR_PARSER_REVISION"
git -C "$BUILD_DIR/car-parser" apply "$PROJECT_DIR/vendor/car-parser/openbundle.patch"

(
  cd "$BUILD_DIR/car-parser"
  wasm-pack build --target web --release --out-dir pkg-openbundle car-wasm
)

mkdir -p "$PROJECT_DIR/web/vendor/car-parser"
cp "$BUILD_DIR/car-parser/car-wasm/pkg-openbundle/car_wasm.js" \
  "$PROJECT_DIR/web/vendor/car-parser/car_wasm.js"
cp "$BUILD_DIR/car-parser/car-wasm/pkg-openbundle/car_wasm_bg.wasm" \
  "$PROJECT_DIR/web/vendor/car-parser/car_wasm_bg.wasm"

echo "Updated web/vendor/car-parser at $CAR_PARSER_REVISION"
