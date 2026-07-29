#!/bin/sh
set -eu

delegate_to_resolvconf() {
    for candidate in /usr/sbin/resolvconf /usr/bin/resolvconf /sbin/resolvconf; do
        if [ -x "$candidate" ]; then
            exec "$candidate" "$@"
        fi
    done
    echo "Neither resolvectl nor resolvconf is available." >&2
    exit 1
}

if [ ! -x /usr/bin/resolvectl ]; then
    delegate_to_resolvconf "$@"
fi

case "${1:-}" in
    -a)
        if [ "$#" -lt 2 ]; then
            exit 1
        fi
        interface=${2##*.}
        dns_servers=
        search_domains=
        while IFS=' ' read -r key value remainder; do
            case "$key" in
                nameserver)
                    dns_servers="$dns_servers $value"
                    ;;
                search)
                    search_domains="$value${remainder:+ $remainder}"
                    ;;
            esac
        done
        if [ -n "$dns_servers" ]; then
            # DNS addresses originate from the validated WireGuard configuration.
            # shellcheck disable=SC2086
            /usr/bin/resolvectl dns "$interface" $dns_servers
        fi
        if [ -n "$search_domains" ]; then
            # shellcheck disable=SC2086
            /usr/bin/resolvectl domain "$interface" $search_domains
        else
            /usr/bin/resolvectl domain "$interface" '~.'
        fi
        ;;
    -d)
        if [ "$#" -lt 2 ]; then
            exit 1
        fi
        interface=${2##*.}
        /usr/bin/resolvectl revert "$interface" >/dev/null 2>&1 || true
        ;;
    *)
        delegate_to_resolvconf "$@"
        ;;
esac
