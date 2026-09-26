#!/bin/sh
# Pre-auth whole-bundle installation. No product process runs with root rights.
set -eu
[ "$(id -u)" -eq 0 ] || exit 1
[ "$#" -eq 1 ] || [ "$#" -eq 2 ] || exit 1
SOURCE=$1
INSTALL_ROOT='/Library/Application Support/Nelomai/common'
DESTINATION="$INSTALL_ROOT/Nelomai.app"
if [ "$#" -eq 2 ]; then
  # Updater already verified the signature; pin the exact bytes across elevation.
  EXPECTED_SHA256=$2
  case "$EXPECTED_SHA256" in *[!0123456789abcdef]*|'') exit 1 ;; esac
  [ "${#EXPECTED_SHA256}" -eq 64 ] || exit 1
  [ -f "$SOURCE" ] && [ ! -L "$SOURCE" ] || exit 1
else
  [ -d "$SOURCE/Contents/Resources/runtime" ] || exit 1
  [ -x "$SOURCE/Contents/MacOS/nelomai-app" ] || exit 1
  [ -z "$(find "$SOURCE" -type l -print -quit)" ] || exit 1
fi
install -d -o root -g wheel -m 0755 '/Library/Application Support/Nelomai' "$INSTALL_ROOT"
STAGING=$(mktemp -d "$INSTALL_ROOT/.install.XXXXXX")
trap 'echo "Common installation staging retained for recovery: $STAGING" >&2' EXIT
if [ "$#" -eq 2 ]; then
  install -o root -g wheel -m 0600 "$SOURCE" "$STAGING/update.tar.gz"
  [ "$(/usr/bin/shasum -a 256 "$STAGING/update.tar.gz" | cut -d ' ' -f 1)" = "$EXPECTED_SHA256" ] || exit 1
  /usr/bin/tar -tzf "$STAGING/update.tar.gz" > "$STAGING/members"
  while IFS= read -r member; do
    case "$member" in Nelomai.app|Nelomai.app/*) ;; *) exit 1 ;; esac
    case "/$member/" in */../*|*/./*) exit 1 ;; esac
  done < "$STAGING/members"
  # No symlinks, hardlinks or special files may escape the private staging tree.
  /usr/bin/tar -tvzf "$STAGING/update.tar.gz" > "$STAGING/types"
  while IFS= read -r member; do
    case "$member" in -*|d*) ;; *) exit 1 ;; esac
  done < "$STAGING/types"
  # The installed root-owned bundle must remain readable/executable by users,
  # independent of the authorization environment. Keep staging itself private.
  (umask 022; /usr/bin/tar -xzf "$STAGING/update.tar.gz" --no-same-owner --no-same-permissions -C "$STAGING")
  /bin/rm "$STAGING/update.tar.gz" "$STAGING/members" "$STAGING/types"
else
  /usr/bin/ditto "$SOURCE" "$STAGING/Nelomai.app"
fi
[ -d "$STAGING/Nelomai.app/Contents/Resources/runtime" ] || exit 1
[ -x "$STAGING/Nelomai.app/Contents/MacOS/nelomai-app" ] || exit 1
# Check the protected copy, too: never follow a link copied during a source race.
[ -z "$(find "$STAGING/Nelomai.app" -type l -print -quit)" ] || exit 1
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
