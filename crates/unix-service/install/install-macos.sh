#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Запустите установщик через sudo." >&2
  exit 1
fi

if [ "$#" -ne 4 ]; then
  echo "Использование: install-macos.sh <uid> <helper> <signed-runtime-layout> <installed-common-broker>" >&2
  exit 1
fi

OWNER_UID=$1
SOURCE_HELPER=$2
SOURCE_LAYOUT=$3
COMMON_BROKER=$4

case "$OWNER_UID" in
  ''|*[!0-9]*)
    echo "UID пользователя должен быть числом." >&2
    exit 1
    ;;
esac

if [ "$OWNER_UID" -eq 0 ]; then
  echo "Helper нельзя привязать к root." >&2
  exit 1
fi

LABEL=ru.nelomai.tunnel
INSTALL_DIR=/Library/PrivilegedHelperTools/$LABEL
PLIST=/Library/LaunchDaemons/$LABEL.plist

install -d -o root -g wheel -m 0755 "$INSTALL_DIR"
PREVIOUS_POINTER=
if [ -f "$INSTALL_DIR/container-manifest.json" ]; then PREVIOUS_POINTER=$(cat "$INSTALL_DIR/container-manifest.json"); fi
ACTIVATION_BACKUP=$(mktemp -d "$INSTALL_DIR/.activation.XXXXXX")
if [ -f "$PLIST" ]; then cp -p "$PLIST" "$ACTIVATION_BACKUP/plist"; fi
PUBLISHED_POINTER=
finish_activation() {
  activation_result=$?
  trap - EXIT
  if [ "$activation_result" -ne 0 ] && [ -n "$PUBLISHED_POINTER" ]; then
    if "$SOURCE_HELPER" rollback-layout "$PUBLISHED_POINTER" "$PREVIOUS_POINTER"; then
      launchctl bootout system/"$LABEL" 2>/dev/null || true
      if [ -f "$ACTIVATION_BACKUP/plist" ]; then
        cp -p "$ACTIVATION_BACKUP/plist" "$PLIST"
        launchctl bootstrap system "$PLIST" || true
      else
        rm -f "$PLIST"
      fi
    else
      echo "Dispatcher activation rollback requires cleanup; previous files are retained." >&2
    fi
  fi
  rm -f "$ACTIVATION_BACKUP/plist"
  rmdir "$ACTIVATION_BACKUP"
  exit "$activation_result"
}
trap finish_activation EXIT
INSTALL_HELPER=$("$SOURCE_HELPER" install-layout "$SOURCE_LAYOUT" "$COMMON_BROKER" "$OWNER_UID")
PUBLISHED_POINTER=$(cat "$INSTALL_DIR/container-manifest.json")
case "$INSTALL_HELPER" in "$INSTALL_DIR"/releases/*/dispatcher/1/nelomai-unix-service) ;; *) exit 1 ;; esac

cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$INSTALL_HELPER</string>
    <string>--dispatcher</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Interactive</string>
  <key>StandardOutPath</key>
  <string>/var/log/nelomai-tunnel.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/nelomai-tunnel.log</string>
</dict>
</plist>
EOF

chown root:wheel "$PLIST"
chmod 0644 "$PLIST"
launchctl bootout system/"$LABEL" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
