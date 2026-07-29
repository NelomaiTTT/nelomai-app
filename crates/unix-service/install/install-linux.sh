#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Запустите установщик через sudo." >&2
  exit 1
fi

if [ "$#" -lt 2 ] || [ "$#" -gt 2 ]; then
  echo "Использование: install-linux.sh <uid-пользователя> <путь-к-helper>" >&2
  exit 1
fi

OWNER_UID=$1
SOURCE_BINARY=$2
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
RESOLVCONF_SOURCE=$SCRIPT_DIR/resolvconf-linux.sh

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

INSTALL_DIR=/usr/local/libexec/nelomai
INSTALL_BINARY=$INSTALL_DIR/nelomai-unix-service
INSTALL_RESOLVCONF=$INSTALL_DIR/resolvconf
UNIT_PATH=/etc/systemd/system/nelomai-tunnel.service

install -d -o root -g root -m 0755 "$INSTALL_DIR"
install -o root -g root -m 0755 "$SOURCE_BINARY" "$INSTALL_BINARY"
install -o root -g root -m 0755 "$RESOLVCONF_SOURCE" "$INSTALL_RESOLVCONF"

cat >"$UNIT_PATH" <<EOF
[Unit]
Description=Nelomai WireGuard tunnel helper
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_BINARY --owner-uid $OWNER_UID
Restart=on-failure
RestartSec=2
User=root
Group=root
UMask=0077
Environment=PATH=$INSTALL_DIR:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=full
PrivateTmp=true
CapabilityBoundingSet=CAP_CHOWN CAP_NET_ADMIN CAP_NET_RAW
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
EOF

chmod 0644 "$UNIT_PATH"
systemctl daemon-reload
systemctl enable nelomai-tunnel.service
systemctl restart nelomai-tunnel.service
