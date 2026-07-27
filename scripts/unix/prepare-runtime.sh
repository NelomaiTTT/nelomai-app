#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "Usage: prepare-runtime.sh <linux|macos> <rust-target>" >&2
  exit 1
fi

PLATFORM=$1
RUST_TARGET=$2
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
HELPER=$ROOT/target/$RUST_TARGET/release/nelomai-unix-service
OUTPUT=$ROOT/src-tauri/platform-runtime

if [ ! -f "$HELPER" ]; then
  echo "Unix helper is missing: $HELPER" >&2
  exit 1
fi

mkdir -p "$OUTPUT"
install -m 0755 "$HELPER" "$OUTPUT/nelomai-unix-service"

if [ "$PLATFORM" = "linux" ]; then
  exit 0
fi
if [ "$PLATFORM" != "macos" ]; then
  echo "Unsupported Unix platform: $PLATFORM" >&2
  exit 1
fi

WIREGUARD_GO_COMMIT=ecfc5a8d54462e18e13c72173e2623d16d8e25a0
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
SOURCE=$WORK/wireguard-go

git init "$SOURCE"
git -C "$SOURCE" remote add origin https://github.com/WireGuard/wireguard-go.git
git -C "$SOURCE" fetch --depth 1 origin "$WIREGUARD_GO_COMMIT"
git -C "$SOURCE" checkout --detach FETCH_HEAD
make -C "$SOURCE"

install -m 0755 "$SOURCE/wireguard-go" "$OUTPUT/wireguard-go"
install -m 0644 "$SOURCE/LICENSE" "$OUTPUT/WIREGUARD-GO-LICENSE.txt"

python3 - "$OUTPUT" "$WIREGUARD_GO_COMMIT" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

output = Path(sys.argv[1])
commit = sys.argv[2]

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

metadata = {
    "wireguard_go_commit": commit,
    "wireguard_go_sha256": sha256(output / "wireguard-go"),
    "helper_sha256": sha256(output / "nelomai-unix-service"),
}
(output / "macos-runtime.json").write_text(
    json.dumps(metadata, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
