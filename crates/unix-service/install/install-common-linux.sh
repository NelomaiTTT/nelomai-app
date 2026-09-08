#!/bin/sh
# Install the exact already-verified AppImage and its complete protected AppDir.
set -eu
[ "$(id -u)" -eq 0 ] || exit 1
[ "$#" -eq 2 ] || exit 1
SOURCE_IMAGE=$1
EXPECTED_SHA256=$2
case "$EXPECTED_SHA256" in *[!0123456789abcdef]*|'') exit 1 ;; esac
[ "${#EXPECTED_SHA256}" -eq 64 ] || exit 1
[ -f "$SOURCE_IMAGE" ] && [ ! -L "$SOURCE_IMAGE" ] || exit 1
INSTALL_ROOT=/usr/local/libexec/nelomai/common
install -d -o root -g root -m 0755 /usr/local/libexec/nelomai "$INSTALL_ROOT"
STAGING=$(mktemp -d "$INSTALL_ROOT/.install.XXXXXX")
trap 'echo "Common installation staging retained for recovery: $STAGING" >&2' EXIT
install -o root -g root -m 0755 "$SOURCE_IMAGE" "$STAGING/Nelomai.AppImage"
[ "$(sha256sum "$STAGING/Nelomai.AppImage" | cut -d ' ' -f 1)" = "$EXPECTED_SHA256" ] || exit 1
(cd "$STAGING" && ./Nelomai.AppImage --appimage-extract >/dev/null)
APPDIR=$STAGING/squashfs-root
COMMON=$APPDIR/usr/bin/nelomai-app
RESOURCES=$APPDIR/usr/lib/Nelomai
[ -x "$COMMON" ] && [ -e "$APPDIR/AppRun" ] || exit 1
[ -d "$RESOURCES/runtime" ] || exit 1
# AppImages legitimately contain internal library symlinks; none may resolve
# outside the complete protected extracted package.
find "$APPDIR" -type l -print | while IFS= read -r link; do
  resolved=$(readlink -f "$link")
  case "$resolved" in "$APPDIR"/*) ;; *) exit 1 ;; esac
done
chown -R root:root "$APPDIR"
chmod -R go-w "$APPDIR"
if [ -d "$INSTALL_ROOT/AppDir/usr/lib/Nelomai/runtime" ]; then
  LD_LIBRARY_PATH="$APPDIR/usr/lib:$APPDIR/usr/lib/x86_64-linux-gnu" "$COMMON" --verify-runtime-layout "$RESOURCES/runtime" "$INSTALL_ROOT/AppDir/usr/lib/Nelomai/runtime"
else
  LD_LIBRARY_PATH="$APPDIR/usr/lib:$APPDIR/usr/lib/x86_64-linux-gnu" "$COMMON" --verify-runtime-layout "$RESOURCES/runtime"
fi
# Prepare every file before activation. If any rename fails, restore both parts
# of the previous package; never leave a new AppDir paired with an old image.
install -o root -g root -m 0755 "$RESOURCES/install-common-linux.sh" "$STAGING/install-common-linux.sh"
APPDIR_ACTIVATED=0
IMAGE_ACTIVATED=0
rollback() {
  if [ "$IMAGE_ACTIVATED" -eq 1 ]; then mv "$INSTALL_ROOT/Nelomai.AppImage" "$STAGING/failed.AppImage" || true; fi
  if [ -e "$STAGING/previous.AppImage" ]; then mv "$STAGING/previous.AppImage" "$INSTALL_ROOT/Nelomai.AppImage" || true; fi
  if [ "$APPDIR_ACTIVATED" -eq 1 ]; then mv "$INSTALL_ROOT/AppDir" "$STAGING/failed-AppDir" || true; fi
  if [ -e "$STAGING/previous-AppDir" ]; then mv "$STAGING/previous-AppDir" "$INSTALL_ROOT/AppDir" || true; fi
  echo "Common installation staging retained for recovery: $STAGING" >&2
}
trap rollback EXIT
if [ -e "$INSTALL_ROOT/AppDir" ]; then mv "$INSTALL_ROOT/AppDir" "$STAGING/previous-AppDir"; fi
mv "$APPDIR" "$INSTALL_ROOT/AppDir"
APPDIR_ACTIVATED=1
if [ -e "$INSTALL_ROOT/Nelomai.AppImage" ]; then mv "$INSTALL_ROOT/Nelomai.AppImage" "$STAGING/previous.AppImage"; fi
mv "$STAGING/Nelomai.AppImage" "$INSTALL_ROOT/Nelomai.AppImage"
IMAGE_ACTIVATED=1
mv "$STAGING/install-common-linux.sh" "$INSTALL_ROOT/install-common-linux.sh"
# The previous complete package is retained root-protected for recovery.
trap - EXIT
