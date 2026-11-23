#!/bin/bash
set -euo pipefail
export LC_ALL=C
umask 077
if [ "$EUID" -ne 0 ]; then
    printf '%s\n' 'root_required' >&2
    exit 1
fi
if [ "$#" -ne 2 ] && [ "$#" -ne 3 ]; then
    printf '%s\n' 'Usage: install.sh --protocol-v2 HOST OUTGOING_INTERFACE' >&2
    exit 1
fi
host=$1
interface=$2
update_mode=${3:-}
if [ -n "$update_mode" ] && [ "$update_mode" != --legacy-1.2.5 ] && [ "$update_mode" != --update-v2 ]; then exit 1; fi
source_dir=$(cd -- "$(dirname -- "$0")" && pwd)
candidate="$source_dir/miga_server"
bash "$source_dir/prepare-dependencies.sh"
for tool in python3 ip iptables conntrack systemctl install sysctl ethtool awk; do
    command -v "$tool" >/dev/null || { printf 'missing_dependency name=%s\n' "$tool" >&2; exit 1; }
done
[ -x "$candidate" ] || { printf '%s\n' 'server_binary_missing' >&2; exit 1; }
"$candidate" --version >/dev/null || { printf '%s\n' 'server_binary_execution_failed' >&2; exit 1; }
if [ -z "$interface" ]; then
    if ! interface=$(ip -o -4 route get 1.1.1.1 | awk 'NR == 1 { for (i = 1; i < NF; i++) if ($i == "dev") { print $(i+1); break } }') ||
        [ -z "$interface" ] || [ "$interface" = lo ] || [[ "$interface" = tun* ]]; then
        printf '%s\n' 'automatic_interface_unavailable' >&2
        exit 1
    fi
fi
if ! [[ "$interface" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || ! ip link show dev "$interface" >/dev/null; then
    printf '%s\n' 'invalid_outgoing_interface' >&2
    exit 1
fi
install -d -m 0700 /var/lib/miga
install -d -m 0700 /etc/miga
prepared=$(mktemp /etc/miga/config.v2.XXXXXX)
trap 'rm -f -- "$prepared"' EXIT
python3 - "$host" "$interface" "$prepared" "$update_mode" "$source_dir" <<'PY'
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys

host, interface, temporary, update_mode, source_dir = sys.argv[1:]
if len(host) > 253 or not host or re.fullmatch(r'[A-Za-z0-9.-]+', host) is None:
    raise SystemExit('invalid_server_host')
if re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', interface) is None:
    raise SystemExit('invalid_interface')
path = Path('/etc/miga/config.json')
current = json.loads(path.read_text()) if path.exists() else {}
if update_mode == '--legacy-1.2.5':
    from importlib.util import spec_from_file_location, module_from_spec
    sys.dont_write_bytecode = True
    spec = spec_from_file_location('miga_update', Path(source_dir) / 'update-v2.py')
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    if not module.configuration(current):
        raise SystemExit('legacy_configuration_expected')
    current = {key: current[key] for key in ('interface', 'log_level', 'dns_server') if key in current}
    current.setdefault('log_level', 'none')
    if current.get('dns_server', '0.0.0.0') == '0.0.0.0':
        current['dns_server'] = ''
    current['protocol'] = 2
    current['virtual_subnet'] = None
if current and current.get('protocol') != 2:
    raise SystemExit('unsupported_existing_protocol')
if current.get('protocol') == 2 and current.get('virtual_subnet') is not None:
    subnet = ipaddress.IPv4Network(current['virtual_subnet'])
else:
    subnet = None
routes = json.loads(subprocess.check_output(['ip', '-j', '-4', 'route', 'show', 'table', 'all']))
networks = []
for route in routes:
    destination = route.get('dst', 'default')
    if destination == 'default':
        continue
    if current.get('protocol') == 2 and route.get('dev') == 'tun_miga':
        continue
    networks.append(ipaddress.IPv4Network(destination, strict=False))
for adapter in json.loads(subprocess.check_output(['ip', '-j', '-4', 'addr', 'show'])):
    if current.get('protocol') == 2 and adapter.get('ifname') == 'tun_miga':
        continue
    for address in adapter.get('addr_info', []):
        if address.get('family') == 'inet':
            networks.append(ipaddress.IPv4Network(f"{address['local']}/{address['prefixlen']}", strict=False))
if subnet is None:
    candidates = [ipaddress.IPv4Network(f'10.{part}.0.0/16') for part in range(64, 255)]
    candidates += [ipaddress.IPv4Network(f'172.{part}.0.0/16') for part in range(16, 32)]
    candidates += [ipaddress.IPv4Network('192.168.0.0/16')]
    subnet = next((item for item in candidates if not any(item.overlaps(other) for other in networks)), None)
if subnet is None or subnet.prefixlen != 16 or not subnet.is_private or any(subnet.overlaps(other) for other in networks):
    raise SystemExit('virtual_subnet_conflict')
ports = current.get('control_ports', [10000, 15000]) if current.get('protocol') == 2 else [10000, 15000]
if len(ports) != 2 or any(type(value) is not int for value in ports) or not (1024 <= ports[0] <= ports[1] <= 65535):
    raise SystemExit('invalid_control_range')
active = subprocess.run(['systemctl', 'is-active', '--quiet', 'miga_server.service']).returncode == 0
owned_inodes = set()
if active and current.get('protocol') == 2:
    process = subprocess.check_output(['systemctl', 'show', '--property=MainPID', '--value', 'miga_server.service'], text=True).strip()
    if not process.isdigit() or int(process) <= 0 or os.path.realpath(f'/proc/{process}/exe') != '/usr/local/miga_server':
        raise SystemExit('running_server_identity_unknown')
    for descriptor in Path(f'/proc/{process}/fd').iterdir():
        try:
            target = os.readlink(descriptor)
        except FileNotFoundError:
            continue
        if target.startswith('socket:[') and target.endswith(']'):
            owned_inodes.add(target[8:-1])
for table in ('/proc/net/udp', '/proc/net/udp6'):
    for line in Path(table).read_text().splitlines()[1:]:
        fields = line.split()
        port = int(fields[1].rsplit(':', 1)[1], 16)
        if ports[0] <= port <= ports[1] and fields[9] not in owned_inodes:
            raise SystemExit('control_port_conflict')
result = dict(current)
result.update(protocol=2, host=host, interface=interface, virtual_subnet=str(subnet), control_ports=ports)
result.setdefault('max_sessions', 64)
result.setdefault('log_level', 'info')
result.setdefault('dns_server', '8.8.8.8')
with open(temporary, 'w') as target:
    json.dump(result, target, indent=2)
    target.write('\n')
    target.flush()
    os.fsync(target.fileno())
os.chmod(temporary, 0o600)
PY
was_active=0
if systemctl is-active --quiet miga_server.service; then was_active=1; fi
[ ! -L /usr/local/miga_server ] && [ ! -L /etc/miga/config.json ] && [ ! -L /etc/systemd/system/miga_server.service ]
if [ -z "$update_mode" ]; then
    rollback=$(mktemp -d /var/lib/miga/install-rollback.XXXXXX)
    enabled_state=$(systemctl is-enabled miga_server.service 2>/dev/null || true)
    forwarding=$(sysctl -n net.ipv4.ip_forward)
    [ "$forwarding" = 0 ] || [ "$forwarding" = 1 ]
    if [ -e /usr/local/miga_server ]; then cp -p -- /usr/local/miga_server "$rollback/binary"; fi
    if [ -e /etc/miga/config.json ]; then cp -p -- /etc/miga/config.json "$rollback/config"; fi
    if [ -e /etc/systemd/system/miga_server.service ]; then cp -p -- /etc/systemd/system/miga_server.service "$rollback/unit"; fi
    if [ -e /etc/sysctl.d/90-miga-v2.conf ]; then cp -p -- /etc/sysctl.d/90-miga-v2.conf "$rollback/sysctl"; fi
    if [ -e /usr/local/bin/miga-server ] || [ -L /usr/local/bin/miga-server ]; then cp -a -- /usr/local/bin/miga-server "$rollback/alias"; fi
fi
cleanup_v2_firewall() {
    python3 - <<'PY'
import shlex
import subprocess

owned = [('filter', 'INPUT', 'MIGA_V2_UDP'), ('filter', 'FORWARD', 'MIGA_V2_FORWARD'),
         ('nat', 'POSTROUTING', 'MIGA_V2_NAT'), ('nat', 'PREROUTING', 'MIGA_V2_DNS')]
for table, parent, target in owned:
    base = ['iptables', '-w', '5', '-t', table]
    result = subprocess.run(base + ['-S', parent], capture_output=True, text=True, timeout=6, check=True)
    for line in result.stdout.splitlines():
        rule = shlex.split(line)
        if rule[:2] != ['-A', parent] or not any(rule[index:index+2] == ['-j', target] for index in range(len(rule)-1)):
            continue
        rule[0] = '-D'
        subprocess.run(base + rule, capture_output=True, timeout=6, check=True)
for table, _, target in owned:
    base = ['iptables', '-w', '5', '-t', table]
    existing = subprocess.run(base + ['-S', target], capture_output=True, timeout=6)
    if existing.returncode == 1:
        continue
    existing.check_returncode()
    subprocess.run(base + ['-F', target], capture_output=True, timeout=6, check=True)
    subprocess.run(base + ['-X', target], capture_output=True, timeout=6, check=True)
PY
}
remove_legacy_icmp_drop() {
    python3 - <<'ICMP_CLEANUP'
import os
from pathlib import Path
import shlex
import stat
import subprocess
import tempfile


def legacy_rule(line):
    try:
        tokens = shlex.split(line, comments=True)
    except ValueError:
        return None
    normalized = tokens[:]
    if normalized[4:6] == ['-m', 'icmp']:
        del normalized[4:6]
    if len(normalized) != 8 or normalized[:4] != ['-A', 'OUTPUT', '-p', 'icmp']:
        return None
    if normalized[4:6] not in (['--icmp-type', '3'], ['--icmp-type', 'destination-unreachable']) or normalized[6:] != ['-j', 'DROP']:
        return None
    return tokens


base = ['iptables', '-w', '5', '-t', 'filter']
snapshot = subprocess.run(base + ['-S', 'OUTPUT'], capture_output=True, text=True, timeout=10, check=True)
removed = 0
for line in snapshot.stdout.splitlines():
    rule = legacy_rule(line)
    if rule is not None:
        subprocess.run(base + ['-D'] + rule[1:], timeout=10, check=True)
        removed += 1
for name in ('/etc/iptables/rules.v4', '/etc/sysconfig/iptables'):
    path = Path(name)
    if not path.exists():
        continue
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise SystemExit('legacy_icmp_persistence_not_regular')
    original = path.read_bytes()
    lines = original.splitlines(keepends=True)
    table = None
    kept = []
    for line in lines:
        text = line.decode('utf-8', errors='surrogateescape').strip()
        if text.startswith('*'):
            table = text[1:]
        if table != 'filter' or legacy_rule(text) is None:
            kept.append(line)
        if text == 'COMMIT':
            table = None
    updated = b''.join(kept)
    if updated == original:
        continue
    descriptor, temporary = tempfile.mkstemp(prefix='.miga-icmp-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as target:
            os.fchown(target.fileno(), metadata.st_uid, metadata.st_gid)
            os.fchmod(target.fileno(), stat.S_IMODE(metadata.st_mode))
            target.write(updated)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
print(f'legacy_icmp_drop_removed count={removed}')
ICMP_CLEANUP
}
restore() {
    result=$?
    trap - ERR
    printf 'server_install_error stage=%s\n' "$stage" >&2
    systemctl stop miga_server.service || true
    previous_v2=0
    if [ -f "$rollback/config" ] && python3 - "$rollback/config" <<'PY'
import json
import sys
raise SystemExit(0 if json.load(open(sys.argv[1])).get('protocol') == 2 else 1)
PY
    then previous_v2=1; fi
    if [ "$previous_v2" -eq 0 ]; then cleanup_v2_firewall || printf '%s\n' 'rollback_firewall_cleanup_failed' >&2; fi
    if [ -f "$rollback/binary" ]; then install -m 0755 "$rollback/binary" /usr/local/miga_server; else rm -f -- /usr/local/miga_server; fi
    if [ -f "$rollback/config" ]; then install -m 0600 "$rollback/config" /etc/miga/config.json; else rm -f -- /etc/miga/config.json; fi
    if [ -f "$rollback/unit" ]; then install -m 0644 "$rollback/unit" /etc/systemd/system/miga_server.service; else rm -f -- /etc/systemd/system/miga_server.service; fi
    if [ -f "$rollback/sysctl" ]; then install -m 0600 "$rollback/sysctl" /etc/sysctl.d/90-miga-v2.conf; else rm -f -- /etc/sysctl.d/90-miga-v2.conf; fi
    rm -f -- /usr/local/bin/miga-server
    if [ -e "$rollback/alias" ] || [ -L "$rollback/alias" ]; then cp -a -- "$rollback/alias" /usr/local/bin/miga-server; fi
    sysctl -w "net.ipv4.ip_forward=$forwarding" >/dev/null || true
    systemctl daemon-reload || true
    if [ "$enabled_state" = enabled ]; then systemctl enable miga_server.service || true; else systemctl disable miga_server.service || true; fi
    if [ "$was_active" -eq 1 ]; then systemctl start miga_server.service || true; fi
    printf 'installation_failed rollback=%s\n' "$rollback" >&2
    exit "$result"
}
stage=stop_service
if [ -z "$update_mode" ]; then trap restore ERR; fi
if [ "$was_active" -eq 1 ]; then systemctl stop miga_server.service; fi
stage=rx_ring
bash "$source_dir/install.sh" --configure-rx-ring
stage=install_files
install -m 0755 "$candidate" /usr/local/miga_server.v2.new
/usr/local/miga_server.v2.new --version >/dev/null
mv -f -- /usr/local/miga_server.v2.new /usr/local/miga_server
mv -f -- "$prepared" /etc/miga/config.json
install -d -m 0755 /usr/local/bin
ln -sfn -- /usr/local/miga_server /usr/local/bin/miga-server
unit=$(mktemp /etc/systemd/system/miga_server.service.XXXXXX)
cat > "$unit" <<'UNIT'
[Unit]
Description=MIGA protocol v2 server
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/miga_server --config /etc/miga/config.json
Restart=on-failure
RestartSec=10
User=root
Group=root
UMask=0077
LimitNOFILE=40960

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "$unit"
mv -f -- "$unit" /etc/systemd/system/miga_server.service
stage=ip_forward
printf '%s\n' 'net.ipv4.ip_forward=1' > /etc/sysctl.d/90-miga-v2.conf
sysctl -p /etc/sysctl.d/90-miga-v2.conf >/dev/null
stage=start_service
systemctl daemon-reload
systemctl enable miga_server.service
systemctl start miga_server.service
systemctl is-active --quiet miga_server.service
stage=legacy_firewall
remove_legacy_icmp_drop
trap - ERR
printf '%s\n' 'installation_complete protocol=2'
