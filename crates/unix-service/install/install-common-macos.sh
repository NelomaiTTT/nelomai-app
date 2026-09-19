#!/bin/sh
# Pre-auth whole-bundle installation. No product process runs with root rights.
set -eu
[ "$(id -u)" -eq 0 ] || exit 1
[ "$#" -eq 1 ] || exit 1
SOURCE_APP=$1
INSTALL_ROOT='/Library/Application Support/Nelomai/common'
DESTINATION="$INSTALL_ROOT/Nelomai.app"
[ -d "$SOURCE_APP/Contents/Resources/runtime" ] || exit 1
[ -x "$SOURCE_APP/Contents/MacOS/nelomai-app" ] || exit 1
# Resource paths and executable hashes are signed; a bundle link may not load
# a user-writable library after the containing directory has been protected.
[ -z "$(find "$SOURCE_APP" -type l -print -quit)" ] || exit 1
install -d -o root -g wheel -m 0755 '/Library/Application Support/Nelomai' "$INSTALL_ROOT"
STAGING=$(mktemp -d "$INSTALL_ROOT/.install.XXXXXX")
trap 'echo "Common installation staging retained for recovery: $STAGING" >&2' EXIT
/usr/bin/ditto "$SOURCE_APP" "$STAGING/Nelomai.app"
chown -R root:wheel "$STAGING/Nelomai.app"
chmod -R go-w "$STAGING/Nelomai.app"
if [ -d "$DESTINATION/Contents/Resources/runtime" ]; then
  "$STAGING/Nelomai.app/Contents/MacOS/nelomai-app" --verify-runtime-layout "$STAGING/Nelomai.app/Contents/Resources/runtime" "$DESTINATION/Contents/Resources/runtime"
else
  "$STAGING/Nelomai.app/Contents/MacOS/nelomai-app" --verify-runtime-layout "$STAGING/Nelomai.app/Contents/Resources/runtime"
fi
/usr/bin/codesign --verify --strict "$STAGING/Nelomai.app"
if [ -e "$DESTINATION" ]; then mv "$DESTINATION" "$STAGING/previous.app"; fi
if ! mv "$STAGING/Nelomai.app" "$DESTINATION"; then
  if [ -e "$STAGING/previous.app" ]; then mv "$STAGING/previous.app" "$DESTINATION"; fi
  exit 1
fi
# Previous bundle remains root-protected for recovery; no broad recursive delete.
trap - EXIT
