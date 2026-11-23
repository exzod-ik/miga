#!/bin/bash
set -euo pipefail

configure_rx_ring() {
    install -d -m 0755 /usr/local/libexec || return 1
    local helper
    helper=$(mktemp /usr/local/libexec/miga-rx-ring.XXXXXX) || return 1
    if ! cat > "$helper" <<'RX_SCRIPT'
#!/bin/bash
set -u
export LC_ALL=C
status=0
for device in /sys/class/net/*; do
    driver=$(readlink -f "$device/device/driver") || continue
    [ "${driver##*/}" = vmxnet3 ] || continue
    iface=${device##*/}
    if ! settings=$(ethtool -g "$iface" 2>&1); then
        printf 'rx_ring_query_failed interface=%s detail=%s\n' "$iface" "$settings" >&2
        status=1
        continue
    fi
    maximum=$(printf '%s\n' "$settings" | awk '/Pre-set maximums:/{section=1;next} /Current hardware settings:/{section=2;next} section==1 && $1=="RX:" {print $2;exit}')
    current=$(printf '%s\n' "$settings" | awk '/Current hardware settings:/{section=1;next} section==1 && $1=="RX:" {print $2;exit}')
    if [[ ! "$maximum" =~ ^[0-9]+$ || ! "$current" =~ ^[0-9]+$ ]]; then
        printf 'rx_ring_invalid_settings interface=%s\n' "$iface" >&2
        status=1
        continue
    fi
    if [ "$maximum" -lt 4096 ]; then
        printf 'rx_ring_unsupported interface=%s maximum=%s target=4096\n' "$iface" "$maximum" >&2
        status=1
        continue
    fi
    if [ "$current" -ne 4096 ]; then
        if ! ethtool -G "$iface" rx 4096; then
            printf 'rx_ring_set_failed interface=%s\n' "$iface" >&2
            status=1
            continue
        fi
    fi
    if ! settings=$(ethtool -g "$iface" 2>&1); then
        printf 'rx_ring_verify_failed interface=%s\n' "$iface" >&2
        status=1
        continue
    fi
    actual=$(printf '%s\n' "$settings" | awk '/Current hardware settings:/{section=1;next} section==1 && $1=="RX:" {print $2;exit}')
    if [ "$actual" != 4096 ]; then
        printf 'rx_ring_verify_failed interface=%s actual=%s\n' "$iface" "$actual" >&2
        status=1
        continue
    fi
    printf 'rx_ring_ready interface=%s rx=4096\n' "$iface"
done
exit "$status"
RX_SCRIPT
    then
        rm -f -- "$helper"
        return 1
    fi
    chmod 0755 "$helper" && mv -f -- "$helper" /usr/local/libexec/miga-rx-ring || { rm -f -- "$helper"; return 1; }
    local unit
    unit=$(mktemp /etc/systemd/system/miga-rx-ring.service.XXXXXX) || return 1
    if ! cat > "$unit" <<'RX_UNIT'
[Unit]
Description=MIGA VMXNET3 receive ring configuration
Wants=network-online.target
After=network-online.target
Before=miga_server.service

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/miga-rx-ring
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
RX_UNIT
    then
        rm -f -- "$unit"
        return 1
    fi
    chmod 0644 "$unit" && mv -f -- "$unit" /etc/systemd/system/miga-rx-ring.service || { rm -f -- "$unit"; return 1; }
    systemctl daemon-reload || return 1
    systemctl enable miga-rx-ring.service || return 1
    systemctl restart miga-rx-ring.service
}

if [ "${1:-}" = "--configure-rx-ring" ]; then
    [ "$EUID" -eq 0 ] || exit 1
    configure_rx_ring
    exit $?
fi
if [ "${1:-}" != "--protocol-v2" ]; then
    printf '%s\n' 'Usage: install.sh --protocol-v2 HOST OUTGOING_INTERFACE' >&2
    exit 1
fi
shift
exec bash "$(cd -- "$(dirname -- "$0")" && pwd)/install-v2.sh" "$@"
