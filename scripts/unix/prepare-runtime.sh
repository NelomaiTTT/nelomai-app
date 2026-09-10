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
AMNEZIAWG_GO_COMMIT=08d68cdae27762c3e07f36bbb12d2bad32f81926

if [ ! -f "$HELPER" ]; then
  echo "Unix helper is missing: $HELPER" >&2
  exit 1
fi

mkdir -p "$OUTPUT"
install -m 0755 "$HELPER" "$OUTPUT/nelomai-unix-service"

# Task 9 signs this exact versioned tree after adding the common/runtime assets.
# No key is accepted here and these hash files are not signature substitutes.
stage_engine_layout() {
  engine_dir=$OUTPUT/engines/latest/0.2.17
  dispatcher_dir=$OUTPUT/dispatcher/1
  mkdir -p "$engine_dir" "$dispatcher_dir"
  for runtime_file in "$OUTPUT"/*; do
    if [ -f "$runtime_file" ]; then cp -p "$runtime_file" "$engine_dir/"; fi
  done
  install -m 0755 "$HELPER" "$dispatcher_dir/nelomai-unix-service"
}

if [ "$PLATFORM" != "linux" ] && [ "$PLATFORM" != "macos" ]; then
  echo "Unsupported Unix platform: $PLATFORM" >&2
  exit 1
fi

if [ "$(git -C "$ROOT/vendor/amneziawg-go" rev-parse HEAD)" != "$AMNEZIAWG_GO_COMMIT" ]; then
  echo "Unexpected AmneziaWG Go source revision" >&2
  exit 1
fi
(
  cd "$ROOT/vendor/amneziawg-go"
  go build -trimpath \
    -ldflags="-s -w -X github.com/amnezia-vpn/amneziawg-go/v3/ipc.socketDirectory=/var/run/wireguard" \
    -o "$OUTPUT/amneziawg-go"
)
chmod 0755 "$OUTPUT/amneziawg-go"
install -m 0644 "$ROOT/vendor/amneziawg-go/LICENSE" "$OUTPUT/AMNEZIAWG-GO-LICENSE.txt"

if [ "$PLATFORM" = "linux" ]; then
  install -m 0755 "$ROOT/crates/unix-service/install/resolvconf-linux.sh" "$OUTPUT/resolvconf"
  python3 - "$OUTPUT" "$AMNEZIAWG_GO_COMMIT" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

output = Path(sys.argv[1])
commit = sys.argv[2]

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

metadata = {
    "amneziawg_go_commit": commit,
    "amneziawg_go_sha256": sha256(output / "amneziawg-go"),
    "helper_sha256": sha256(output / "nelomai-unix-service"),
}
(output / "linux-runtime.json").write_text(
    json.dumps(metadata, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
  stage_engine_layout
  exit 0
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

python3 - "$OUTPUT" "$WIREGUARD_GO_COMMIT" "$AMNEZIAWG_GO_COMMIT" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

output = Path(sys.argv[1])
commit = sys.argv[2]
amnezia_commit = sys.argv[3]

def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

metadata = {
    "wireguard_go_commit": commit,
    "wireguard_go_sha256": sha256(output / "wireguard-go"),
    "amneziawg_go_commit": amnezia_commit,
    "amneziawg_go_sha256": sha256(output / "amneziawg-go"),
    "helper_sha256": sha256(output / "nelomai-unix-service"),
}
(output / "macos-runtime.json").write_text(
    json.dumps(metadata, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
stage_engine_layout
