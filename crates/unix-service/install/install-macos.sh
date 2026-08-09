#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Запустите установщик через sudo." >&2
  exit 1
fi

if [ "$#" -ne 4 ]; then
  echo "Использование: install-macos.sh <uid-пользователя> <путь-к-helper> <путь-к-wireguard-go> <путь-к-amneziawg-go>" >&2
  exit 1
fi

OWNER_UID=$1
SOURCE_HELPER=$2
SOURCE_WIREGUARD_GO=$3
SOURCE_AMNEZIAWG_GO=$4

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
INSTALL_HELPER=$INSTALL_DIR/nelomai-unix-service
INSTALL_WIREGUARD_GO=$INSTALL_DIR/wireguard-go
INSTALL_AMNEZIAWG_GO=$INSTALL_DIR/amneziawg-go
PLIST=/Library/LaunchDaemons/$LABEL.plist

install -d -o root -g wheel -m 0755 "$INSTALL_DIR"
install -o root -g wheel -m 0755 "$SOURCE_HELPER" "$INSTALL_HELPER"
install -o root -g wheel -m 0755 "$SOURCE_WIREGUARD_GO" "$INSTALL_WIREGUARD_GO"
install -o root -g wheel -m 0755 "$SOURCE_AMNEZIAWG_GO" "$INSTALL_AMNEZIAWG_GO"

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
    <string>--owner-uid</string>
    <string>$OWNER_UID</string>
    <string>--wireguard-go</string>
    <string>$INSTALL_WIREGUARD_GO</string>
    <string>--amneziawg-go</string>
    <string>$INSTALL_AMNEZIAWG_GO</string>
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
