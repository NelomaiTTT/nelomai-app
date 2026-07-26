#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Запустите установщик через sudo." >&2
  exit 1
fi

if [ "$#" -lt 2 ] || [ "$#" -gt 2 ]; then
  echo "Использование: install-linux.sh <пользователь> <путь-к-helper>" >&2
  exit 1
fi

OWNER_NAME=$1
SOURCE_BINARY=$2
OWNER_UID=$(id -u "$OWNER_NAME")

if [ "$OWNER_UID" -eq 0 ]; then
  echo "Helper нельзя привязать к root." >&2
  exit 1
fi

INSTALL_DIR=/usr/local/libexec/nelomai
INSTALL_BINARY=$INSTALL_DIR/nelomai-unix-service
UNIT_PATH=/etc/systemd/system/nelomai-tunnel.service

install -d -o root -g root -m 0755 "$INSTALL_DIR"
install -o root -g root -m 0755 "$SOURCE_BINARY" "$INSTALL_BINARY"

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
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=full
PrivateTmp=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
EOF

chmod 0644 "$UNIT_PATH"
systemctl daemon-reload
systemctl enable --now nelomai-tunnel.service
