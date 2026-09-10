#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Запустите установщик через sudo." >&2
  exit 1
fi

if [ "$#" -ne 4 ]; then
  echo "Использование: install-linux.sh <uid> <helper> <signed-runtime-layout> <installed-common-broker>" >&2
  exit 1
fi

OWNER_UID=$1
SOURCE_BINARY=$2
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

INSTALL_DIR=/usr/local/libexec/nelomai
UNIT_PATH=/etc/systemd/system/nelomai-tunnel.service

install -d -o root -g root -m 0755 "$INSTALL_DIR"
PREVIOUS_POINTER=
if [ -f "$INSTALL_DIR/container-manifest.json" ]; then PREVIOUS_POINTER=$(cat "$INSTALL_DIR/container-manifest.json"); fi
ACTIVATION_BACKUP=$(mktemp -d "$INSTALL_DIR/.activation.XXXXXX")
if [ -f "$UNIT_PATH" ]; then cp -p "$UNIT_PATH" "$ACTIVATION_BACKUP/unit"; fi
PUBLISHED_POINTER=
finish_activation() {
  activation_result=$?
  trap - EXIT
  if [ "$activation_result" -ne 0 ] && [ -n "$PUBLISHED_POINTER" ]; then
    if "$SOURCE_BINARY" rollback-layout "$PUBLISHED_POINTER" "$PREVIOUS_POINTER"; then
      if [ -f "$ACTIVATION_BACKUP/unit" ]; then
        cp -p "$ACTIVATION_BACKUP/unit" "$UNIT_PATH"
        systemctl daemon-reload
        systemctl restart nelomai-tunnel.service || true
      else
        rm -f "$UNIT_PATH"
        systemctl daemon-reload
      fi
    else
      echo "Dispatcher activation rollback requires cleanup; previous files are retained." >&2
    fi
  fi
  rm -f "$ACTIVATION_BACKUP/unit"
  rmdir "$ACTIVATION_BACKUP"
  exit "$activation_result"
}
trap finish_activation EXIT
INSTALL_BINARY=$("$SOURCE_BINARY" install-layout "$SOURCE_LAYOUT" "$COMMON_BROKER" "$OWNER_UID")
PUBLISHED_POINTER=$(cat "$INSTALL_DIR/container-manifest.json")
case "$INSTALL_BINARY" in "$INSTALL_DIR"/releases/*/dispatcher/1/nelomai-unix-service) ;; *) exit 1 ;; esac

cat >"$UNIT_PATH" <<EOF
[Unit]
Description=Nelomai WireGuard tunnel helper
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$INSTALL_BINARY --dispatcher
Restart=on-failure
RestartSec=2
User=root
Group=root
UMask=0077
Environment=PATH=$INSTALL_DIR:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=full
# Dispatcher mutation locks and engine lifecycle markers live beside releases.
ReadWritePaths=$INSTALL_DIR
PrivateTmp=true
# Required to resolve /proc/<unprivileged-peer-pid>/exe for broker identity.
CapabilityBoundingSet=CAP_CHOWN CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
EOF

chmod 0644 "$UNIT_PATH"
systemctl daemon-reload
systemctl enable nelomai-tunnel.service
systemctl restart nelomai-tunnel.service
