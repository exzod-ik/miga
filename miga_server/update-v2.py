import base64
import configparser
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time


SERVICE = 'miga_server.service'
CHAINS = {'filter': {'MIGA_V2_UDP', 'MIGA_V2_FORWARD'}, 'nat': {'MIGA_V2_NAT', 'MIGA_V2_DNS'}}
PERSISTENCE = ('/etc/iptables/rules.v4', '/etc/sysconfig/iptables')
FILES = ['/usr/local/miga_server', '/etc/miga/config.json', '/etc/systemd/system/miga_server.service',
         '/etc/sysctl.d/90-miga-v2.conf', '/usr/local/bin/miga-server',
         '/usr/local/libexec/miga-rx-ring', '/etc/systemd/system/miga-rx-ring.service',
         '/etc/iptables/rules.v4', '/etc/sysconfig/iptables']


def run(*arguments, check=True, timeout=45):
    with subprocess.Popen(list(arguments), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise
        result = subprocess.CompletedProcess(arguments, process.returncode, stdout, stderr)
        if check:
            result.check_returncode()
        return result


def configuration(value):
    if type(value) is not dict:
        raise ValueError('invalid_server_configuration')
    protocol = value.get('protocol')
    interface = value.get('interface', '')
    automatic = interface == '' and ('protocol' not in value or type(protocol) is int and protocol == 1)
    if not automatic and (not isinstance(interface, str) or re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', interface) is None):
        raise ValueError('invalid_interface')
    if value.get('log_level', 'info') not in ('none', 'error', 'warning', 'info', 'debug'):
        raise ValueError('invalid_log_level')
    dns = value.get('dns_server', '')
    if not isinstance(dns, str):
        raise ValueError('invalid_dns_server')
    if dns != '':
        ipaddress.IPv4Address(dns)
    if type(protocol) is int and protocol == 2:
        if value.get('state_directory', '/var/lib/miga') != '/var/lib/miga':
            raise ValueError('unsupported_state_directory')
        return False
    if 'protocol' in value and (type(protocol) is not int or protocol != 1):
        raise ValueError('unsupported_existing_protocol')
    if set(value) - {'protocol', 'client_ports', 'encryption', 'interface', 'dns_server', 'log_level'}:
        raise ValueError('unknown_legacy_configuration')
    ports = value.get('client_ports', {'start': 10000, 'end': 15000})
    if type(ports) is not dict or set(ports) != {'start', 'end'} or any(type(ports[k]) is not int for k in ports):
        raise ValueError('invalid_legacy_ports')
    if not 1024 <= ports['start'] <= ports['end'] <= 65535:
        raise ValueError('invalid_legacy_ports')
    keys = value.get('encryption')
    if type(keys) is not dict or set(keys) != {'xor_key', 'swap_key'}:
        raise ValueError('invalid_legacy_keys')
    for key, size in (('xor_key', 128), ('swap_key', 8)):
        if not isinstance(keys[key], str) or len(base64.b64decode(keys[key], validate=True)) != size:
            raise ValueError('invalid_legacy_keys')
    return True


def outgoing_interface(config):
    interface = config.get('interface', '')
    if not interface:
        routes = json.loads(run('ip', '-j', '-4', 'route', 'get', '1.1.1.1').stdout)
        if type(routes) is not list or len(routes) != 1 or type(routes[0]) is not dict or routes[0].get('type', 'unicast') != 'unicast':
            raise ValueError('automatic_interface_unavailable')
        interface = routes[0].get('dev')
    if not isinstance(interface, str) or re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', interface) is None or interface == 'lo' or interface.startswith('tun'):
        raise ValueError('invalid_outgoing_interface')
    run('ip', 'link', 'show', 'dev', interface)
    return interface


def owned(table, rule):
    if len(rule) < 2 or rule[0] != '-A':
        return False
    if rule[1] in CHAINS.get(table, set()):
        return True
    if any(rule[i:i + 2] == ['-j', chain] for chain in CHAINS.get(table, set()) for i in range(len(rule) - 1)):
        return True
    if table == 'nat':
        return rule == ['-A', 'POSTROUTING', '-s', '10.0.0.0/24', '!', '-o', 'tun_miga', '-j', 'MASQUERADE']
    normalized = rule[:]
    if normalized[4:6] == ['-m', 'icmp']:
        del normalized[4:6]
    return table == 'filter' and normalized in (
        ['-A', 'OUTPUT', '-p', 'icmp', '--icmp-type', '3', '-j', 'DROP'],
        ['-A', 'OUTPUT', '-p', 'icmp', '--icmp-type', 'destination-unreachable', '-j', 'DROP'])


def firewall_snapshot():
    return {table: [shlex.split(line) for line in run('iptables', '-w', '5', '-t', table, '-S').stdout.splitlines()]
            for table in CHAINS}


def restore_firewall(snapshot):
    current = firewall_snapshot()
    for table, rules in current.items():
        base = ['iptables', '-w', '5', '-t', table]
        for rule in rules:
            if owned(table, rule) and rule[1] not in CHAINS[table]:
                run(*base, '-D', *rule[1:])
        existing = {rule[1] for rule in rules if rule[0] == '-N' and rule[1] in CHAINS[table]}
        for chain in existing:
            run(*base, '-F', chain)
        for chain in existing:
            run(*base, '-X', chain)
        for rule in snapshot[table]:
            if rule[0] == '-N' and rule[1] in CHAINS[table]:
                run(*base, *rule)
        positions = {}
        for rule in snapshot[table]:
            if rule[0] != '-A':
                continue
            chain = rule[1]
            positions[chain] = positions.get(chain, 0) + 1
            if not owned(table, rule):
                continue
            if chain in CHAINS[table]:
                run(*base, *rule)
            else:
                length = sum(line.startswith('-A ') for line in run(*base, '-S', chain).stdout.splitlines())
                run(*base, '-I', chain, str(min(positions[chain], length + 1)), *rule[2:])


class Backup:
    def __init__(self, directory):
        self.directory = directory
        self.paths = []

    def save(self, name):
        path = Path(name)
        if path.is_symlink() and name != '/usr/local/bin/miga-server':
            raise ValueError('unsafe_backup_symlink')
        destination = self.directory / str(len(self.paths))
        exists = path.exists() or path.is_symlink()
        if exists:
            run('cp', '-a', '--', str(path), str(destination))
        self.paths.append((path, destination, exists))
        (self.directory / 'manifest.json').write_text(json.dumps([(str(p), str(d), e) for p, d, e in self.paths]))

    def restore(self):
        failures = []
        for path, source, existed in reversed(self.paths):
            try:
                if any(str(path).replace('\\', '/').endswith(name) for name in PERSISTENCE):
                    if (not existed and path.exists()) or (existed and not path.is_file()):
                        raise ValueError('persistent_firewall_conflict')
                    if existed and persistent_unowned(path) != persistent_unowned(source):
                        raise ValueError('persistent_firewall_conflict')
                if existed:
                    temporary = path.with_name(path.name + '.miga-restore')
                    if temporary.exists() or temporary.is_symlink():
                        raise ValueError('rollback_temporary_exists')
                    run('cp', '-a', '--', str(source), str(temporary))
                    if path.is_dir() and not path.is_symlink():
                        displaced = path.with_name(path.name + '.miga-displaced')
                        if displaced.exists() or displaced.is_symlink():
                            raise ValueError('rollback_displaced_exists')
                        os.replace(path, displaced)
                        try:
                            os.replace(temporary, path)
                        except BaseException:
                            os.replace(displaced, path)
                            raise
                        shutil.rmtree(displaced)
                    else:
                        os.replace(temporary, path)
                elif path.exists() or path.is_symlink():
                    if path.is_dir() and not path.is_symlink():
                        shutil.rmtree(path)
                    else:
                        path.unlink()
            except BaseException as error:
                failures.append(str(path))
                reason = str(error) if type(error) is ValueError and re.fullmatch(r'[a-z0-9_]+', str(error)) else type(error).__name__
                print('server_update_restore_failed path=' + json.dumps(str(path)) + ' reason=' + reason, file=sys.stderr)
        if failures:
            raise RuntimeError('backup_restore_failed')


def persistent_unowned(path):
    table = None
    result = []
    for line in path.read_bytes().splitlines(keepends=True):
        text = line.decode('utf-8', errors='surrogateescape').strip()
        if text.startswith('*'):
            table = text[1:]
        rule = shlex.split(text, comments=True) if text.startswith('-A ') else []
        if not owned(table, rule):
            result.append(line)
        if text == 'COMMIT':
            table = None
    return b''.join(result)


def remove_legacy_nat():
    for rule in firewall_snapshot()['nat']:
        if owned('nat', rule) and rule[1] == 'POSTROUTING' and rule[-1] == 'MASQUERADE':
            run('iptables', '-w', '5', '-t', 'nat', '-D', *rule[1:])
    for name in ('/etc/iptables/rules.v4', '/etc/sysconfig/iptables'):
        path = Path(name)
        if not path.exists():
            continue
        metadata = path.stat()
        table = None
        kept = []
        original = path.read_bytes()
        for line in original.splitlines(keepends=True):
            text = line.decode('utf-8', errors='surrogateescape').strip()
            if text.startswith('*'):
                table = text[1:]
            rule = shlex.split(text) if table == 'nat' and text.startswith('-A ') else []
            if not (rule and rule[1] == 'POSTROUTING' and owned('nat', rule) and rule[-1] == 'MASQUERADE'):
                kept.append(line)
            if text == 'COMMIT':
                table = None
        updated = b''.join(kept)
        if updated != original:
            descriptor, temporary = tempfile.mkstemp(prefix='.miga-nat-', dir=path.parent)
            try:
                with os.fdopen(descriptor, 'wb') as output:
                    os.fchown(output.fileno(), metadata.st_uid, metadata.st_gid)
                    os.fchmod(output.fileno(), stat.S_IMODE(metadata.st_mode))
                    output.write(updated)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)


def service_state(service):
    enabled = run('systemctl', 'is-enabled', service, check=False).stdout.strip()
    if enabled not in ('enabled', 'disabled'):
        raise ValueError('unsupported_service_state')
    active = run('systemctl', 'is-active', '--quiet', service, check=False).returncode == 0
    return active, enabled


def restore_service(service, state):
    active, enabled = state
    run('systemctl', 'enable' if enabled == 'enabled' else 'disable', service)
    run('systemctl', 'start' if active else 'stop', service)


def service_identity(legacy, active):
    unit = configparser.ConfigParser(interpolation=None, strict=True)
    unit.read_string(Path('/etc/systemd/system/miga_server.service').read_text())
    section = unit['Service']
    expected = ['/usr/local/miga_server'] if legacy else ['/usr/local/miga_server', '--config', '/etc/miga/config.json']
    if shlex.split(section.get('ExecStart', '')) != expected or any(section.get(key) for key in ('RootDirectory', 'RootImage')):
        raise ValueError('unsupported_service_command')
    if active:
        process = run('systemctl', 'show', '--property=MainPID', '--value', SERVICE).stdout.strip()
        if not process.isdigit() or int(process) <= 0 or os.readlink('/proc/' + process + '/exe') != '/usr/local/miga_server':
            raise ValueError('running_server_identity_unknown')
        arguments = Path('/proc/' + process + '/cmdline').read_bytes().split(b'\0')
        if arguments[-1:] == [b'']:
            arguments.pop()
        if arguments != [argument.encode() for argument in expected]:
            raise ValueError('running_server_command_unknown')


def legacy_ready():
    deadline = time.monotonic() + 25
    identity = None
    stable = 0
    while time.monotonic() < deadline:
        process = run('systemctl', 'show', '--property=MainPID', '--value', SERVICE).stdout.strip()
        if not process.isdigit() or int(process) <= 0 or run('systemctl', 'is-active', '--quiet', SERVICE, check=False).returncode:
            raise RuntimeError('legacy_restart_failed')
        if os.readlink('/proc/' + process + '/exe') != '/usr/local/miga_server':
            raise RuntimeError('legacy_restart_identity_unknown')
        available = any(owned('filter', rule) and rule[1:4] == ['OUTPUT', '-p', 'icmp'] for rule in firewall_snapshot()['filter'])
        stable = stable + 1 if available and process == identity else int(available)
        identity = process
        if stable >= 4:
            return
        time.sleep(1)
    raise RuntimeError('legacy_restart_timeout')


def rings():
    result = {}
    for path in Path('/sys/class/net').iterdir():
        if (path / 'device/driver').resolve().name != 'vmxnet3':
            continue
        text = run('ethtool', '-g', path.name).stdout
        current = text.split('Current hardware settings:', 1)[1]
        result[path.name] = re.search(r'^RX:\s*(\d+)\s*$', current, re.MULTILINE).group(1)
    return result


def ready():
    deadline = time.monotonic() + 25
    identity = None
    stable = 0
    while time.monotonic() < deadline:
        process = run('systemctl', 'show', '--property=MainPID', '--value', SERVICE).stdout.strip()
        if not process.isdigit() or int(process) <= 0 or run('systemctl', 'is-active', '--quiet', SERVICE, check=False).returncode:
            raise RuntimeError('server_start_failed')
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as probe:
                probe.settimeout(2)
                probe.connect('/var/lib/miga/admin.sock')
                probe.sendall(b'{"scope":"settings","operation":"get"}')
                available = type(json.loads(probe.recv(65536)).get('max_sessions')) is int
        except (OSError, ValueError):
            available = False
        if available:
            stable = stable + 1 if process == identity else 1
            identity = process
            if stable >= 4:
                return
        else:
            stable = 0
        time.sleep(1)
    raise RuntimeError('server_readiness_timeout')


def update(source, host):
    preparation = run('bash', str(source / 'prepare-dependencies.sh'), check=False, timeout=330)
    if preparation.returncode:
        for line in preparation.stderr.splitlines():
            if re.fullmatch(r'server_dependency_error manager=[a-z-]+ stage=[a-z]+ reason=[a-z0-9_]+ code=[0-9]+', line):
                print(line, file=sys.stderr)
        raise RuntimeError('dependency_preparation_failed')
    for dependency in ('python3', 'ip', 'iptables', 'conntrack', 'systemctl', 'install', 'sysctl', 'ethtool', 'bash', 'cp'):
        if shutil.which(dependency) is None:
            raise ValueError('missing_dependency_' + dependency)
    if not host or len(host) > 253 or re.fullmatch(r'[A-Za-z0-9.-]+', host) is None:
        raise ValueError('invalid_server_host')
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate_configuration_key')
            result[key] = value
        return result
    config = json.loads(Path('/etc/miga/config.json').read_text(), object_pairs_hook=unique_object)
    legacy = configuration(config)
    if not legacy:
        host = config.get('host')
        if not isinstance(host, str) or not host or len(host) > 253 or re.fullmatch(r'[A-Za-z0-9.-]+', host) is None:
            raise ValueError('invalid_existing_server_host')
    if legacy and run('/usr/local/miga_server', '--version').stdout.strip() != '1.2.5':
        raise ValueError('unsupported_legacy_version')
    expected_version = json.loads((source / 'ServerVersion.inc').read_text(encoding='utf-8'))
    if not isinstance(expected_version, str) or re.fullmatch(r'[0-9]+(?:\.[0-9]+){2,3}', expected_version) is None:
        raise ValueError('invalid_expected_server_version')
    if run(str(source / 'miga_server'), '--version').stdout.strip() != expected_version:
        raise ValueError('unexpected_candidate_version')
    interface = outgoing_interface(config)
    state = service_state(SERVICE)
    if run('systemctl', 'show', '--property=FragmentPath', '--value', SERVICE).stdout.strip() != '/etc/systemd/system/miga_server.service':
        raise ValueError('unsupported_service_unit_path')
    if run('systemctl', 'show', '--property=DropInPaths', '--value', SERVICE).stdout.strip():
        raise ValueError('unsupported_service_overrides')
    if run('systemctl', 'show', '--property=NeedDaemonReload', '--value', SERVICE).stdout.strip() != 'no':
        raise ValueError('service_unit_reload_required')
    service_identity(legacy, state[0])
    rx_state = service_state('miga-rx-ring.service') if Path('/etc/systemd/system/miga-rx-ring.service').exists() else None
    ring_state = rings()
    forwarding = run('sysctl', '-n', 'net.ipv4.ip_forward').stdout.strip()
    if forwarding not in ('0', '1'):
        raise ValueError('invalid_forwarding_state')
    network = firewall_snapshot()
    directory = Path(tempfile.mkdtemp(prefix='miga-update-', dir='/var/backups'))
    os.chmod(directory, 0o700)
    backup = Backup(directory)
    config_directory = Path('/etc/miga').stat()
    for path in FILES:
        backup.save(path)
    (directory / 'network.json').write_text(json.dumps(network))
    (directory / 'service.json').write_text(json.dumps({'server': state, 'rx': rx_state, 'rings': ring_state, 'forwarding': forwarding,
                                                     'config_directory': [config_directory.st_uid, config_directory.st_gid, stat.S_IMODE(config_directory.st_mode)]}))
    stopped = False
    try:
        stopped = True
        run('systemctl', 'stop', SERVICE)
        backup.save('/var/lib/miga')
        run('bash', str(source / 'install-v2.sh'), host, interface, '--legacy-1.2.5' if legacy else '--update-v2', timeout=180)
        if legacy:
            remove_legacy_nat()
        ready()
        if not state[0]:
            run('systemctl', 'stop', SERVICE)
        run('systemctl', 'enable' if state[1] == 'enabled' else 'disable', SERVICE)
        print('server_update_complete protocol=2 migration=' + str(int(legacy)) + ' backup=' + str(directory))
    except BaseException:
        failures = []
        def attempt(action):
            try:
                action()
                return True
            except BaseException:
                failures.append(True)
                return False
        if stopped:
            attempt(lambda: run('systemctl', 'stop', SERVICE))
            if Path('/etc/systemd/system/miga-rx-ring.service').exists():
                attempt(lambda: run('systemctl', 'stop', 'miga-rx-ring.service'))
                if rx_state is None:
                    attempt(lambda: run('systemctl', 'disable', 'miga-rx-ring.service'))
            restored = attempt(backup.restore)
            attempt(lambda: run('sysctl', '-w', 'net.ipv4.ip_forward=' + forwarding))
            attempt(lambda: os.chmod('/etc/miga', stat.S_IMODE(config_directory.st_mode)))
            attempt(lambda: os.chown('/etc/miga', config_directory.st_uid, config_directory.st_gid))
            attempt(lambda: run('systemctl', 'daemon-reload'))
            if rx_state is not None:
                attempt(lambda: restore_service('miga-rx-ring.service', rx_state))
            for interface, value in ring_state.items():
                attempt(lambda i=interface, v=value: run('ethtool', '-G', i, 'rx', v))
            if restored:
                restarted = attempt(lambda: restore_service(SERVICE, state))
                if restarted and state[0]:
                    attempt(legacy_ready if legacy else ready)
            attempt(lambda: restore_firewall(network))
        print('server_update_failed rollback=' + ('incomplete' if failures else 'complete') + ' backup=' + str(directory), file=sys.stderr)
        raise


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2:
        raise ValueError('usage_update_v2_HOST_as_root')
    os.umask(0o077)
    def interrupted(signum, frame):
        raise RuntimeError('server_update_interrupted')
    for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(signum, interrupted)
    with open('/run/miga-update.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        update(Path(__file__).resolve().parent, sys.argv[1])


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        reason = str(error) if type(error) in (ValueError, RuntimeError) and re.fullmatch(r'[a-z0-9_]+', str(error)) else type(error).__name__
        print('server_update_error reason=' + reason, file=sys.stderr)
        sys.exit(1)
