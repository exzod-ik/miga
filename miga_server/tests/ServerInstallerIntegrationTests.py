import copy
import json
import os
import re
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import ServerUpdateMigrationTests as migration


TEST_SCRIPT = Path(__file__).resolve()
SOURCE = TEST_SCRIPT.parents[1]
BASH = os.environ.get('MIGA_TEST_BASH', 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else 'bash')


def adapter(root, arguments):
    state_path = root / 'fixture-state.json'
    state = json.loads(state_path.read_text())
    state['commands'].append(arguments)
    command, *args = arguments
    output = ''
    code = 0
    failure = state.get('failure')
    if command == 'ip':
        if args in (['-j', '-4', 'route', 'show', 'table', 'all'], ['-j', '-4', 'addr', 'show']):
            output = json.dumps([{'dst': '10.0.0.0/8'}, {'dst': '172.16.0.0/12'}, {'dst': '192.168.0.0/16'}]) if failure == 'subnet' and 'route' in args else '[]'
        elif args == ['-o', '-4', 'route', 'get', '1.1.1.1']:
            output = '' if failure == 'route' else '1.1.1.1 via 192.0.2.1 dev ens3 src 192.0.2.2\n'
            code = int(failure == 'route')
        elif args[:3] == ['link', 'show', 'dev']:
            code = int(args[3] == 'missing0')
        else:
            raise AssertionError(arguments)
    elif command == 'systemctl':
        operation = args[0]
        service = args[-1]
        if operation == 'is-active':
            code = 0 if state['active'] else 3
        elif operation == 'is-enabled':
            output = state['enabled']
        elif operation == 'show':
            output = '123'
        elif operation == 'stop':
            state['active'] = False
        elif operation == 'start':
            state['active'] = True
            if service == migration.module.SERVICE:
                state['rules']['filter'] += [['-N', 'MIGA_V2_UDP'], ['-A', 'INPUT', '-j', 'MIGA_V2_UDP'], ['-A', 'MIGA_V2_UDP', '-j', 'ACCEPT']]
                (root / 'var/lib/miga/new-secret').write_text('fixture')
                if failure == 'start':
                    code = 1
        elif operation == 'restart' and service == 'miga-rx-ring.service':
            state['ring'] = '4096'
            code = int(failure == 'rx')
        elif operation in ('enable', 'disable'):
            if service == migration.module.SERVICE:
                state['enabled'] = 'enabled' if operation == 'enable' else 'disabled'
        elif operation != 'daemon-reload':
            raise AssertionError(arguments)
    elif command == 'sysctl':
        if args[0] == '-n':
            output = state['forwarding']
        elif args[0] == '-p':
            state['forwarding'] = '1'
            code = int(failure == 'sysctl')
        else:
            raise AssertionError(arguments)
    elif command == 'iptables':
        if args[:4] != ['-w', '5', '-t', 'filter']:
            raise AssertionError(arguments)
        if args[4:] == ['-S', 'OUTPUT']:
            output = '\n'.join(' '.join(rule) for rule in state['rules']['filter'] if rule[1] == 'OUTPUT')
        elif args[4] == '-D':
            state['rules']['filter'].remove(['-A'] + args[5:])
            code = int(failure == 'icmp')
        else:
            raise AssertionError(arguments)
    elif command in ('conntrack', 'ethtool'):
        if args:
            raise AssertionError(arguments)
    elif command == 'install':
        destinations = args[3:] if args[0] == '-d' else args[-1:]
        for destination in destinations:
            if not Path(destination).resolve().is_relative_to(root.resolve()):
                raise AssertionError(arguments)
        if args[0] == '-d':
            for destination in destinations:
                Path(destination).mkdir(parents=True, exist_ok=True)
        elif args[:2] == ['-m', '0755']:
            if failure == 'binary':
                code = 1
            else:
                shutil.copyfile(args[-2], args[-1])
                os.chmod(args[-1], 0o755)
        else:
            raise AssertionError(arguments)
    else:
        raise AssertionError(arguments)
    state_path.write_text(json.dumps(state))
    return subprocess.CompletedProcess(arguments, code, output, '')


def embedded_python(root):
    script = sys.stdin.read()
    def execute(arguments, **kwargs):
        response = adapter(root, arguments)
        if kwargs.get('check'):
            response.check_returncode()
        if not kwargs.get('text') and not kwargs.get('universal_newlines'):
            response.stdout = response.stdout.encode()
            response.stderr = response.stderr.encode()
        return response
    def output(arguments, **kwargs):
        response = execute(arguments, check=True, **kwargs)
        return response.stdout
    with patch.object(subprocess, 'run', side_effect=execute), patch.object(subprocess, 'check_output', side_effect=output), patch.object(os, 'fchown', create=True):
        exec(compile(script, 'actual-installer-python', 'exec'), {'__name__': '__main__'})


class IntegratedEnvironment(migration.Environment):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rules['filter'].append(migration.ICMP[:])
        self.original_rules = copy.deepcopy(self.rules)

    def install(self, arguments):
        stage = self.root / 'stage'
        stage.mkdir()
        for directory in ('proc/net', 'proc/1', 'sys/class/net', 'etc/sysctl.d', 'usr/local/bin'):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        (self.root / 'proc/1/comm').write_text('systemd\n')
        for table in ('udp', 'udp6'):
            row = '0: 00000000:2710 00000000:0000 07 0 0 0 0 0 999\n' if table == 'udp' and self.failure == 'ports' else ''
            (self.root / 'proc/net' / table).write_text('header\n' + row)
        for name in ('install.sh', 'install-v2.sh', 'prepare-dependencies.sh'):
            text = (SOURCE / name).read_text()
            text = re.sub(r'/(?:usr/local|etc|var/lib|proc|sys)(?=/)', lambda match: self.root.as_posix() + match.group(), text)
            text = text.replace('[ "$EUID" -eq 0 ]', 'true').replace('[ "$EUID" -ne 0 ]', 'false')
            (stage / name).write_bytes(text.encode('utf-8'))
        (stage / 'update-v2.py').write_bytes((SOURCE / 'update-v2.py').read_bytes())
        (stage / 'ServerVersion.inc').write_bytes((SOURCE / 'ServerVersion.inc').read_bytes())
        version = json.loads((SOURCE / 'ServerVersion.inc').read_text())
        (stage / 'miga_server').write_bytes(f'#!/bin/bash\n[ "$1" = --version ] || exit 99\nprintf "{version}\\n"\n'.encode('utf-8'))
        os.chmod(stage / 'miga_server', 0o755)
        state = dict(active=self.active, enabled=self.enabled, ring=self.ring, forwarding=self.forwarding,
                     rules=self.rules, failure=self.failure, commands=[])
        state_path = self.root / 'fixture-state.json'
        state_path.write_text(json.dumps(state))
        invocation = shlex.join([sys.executable.replace('\\', '/'), TEST_SCRIPT.as_posix()])
        fixture_root = shlex.quote(self.root.as_posix())
        conversion = 'local values=() value; for value in "$@"; do if [[ "$value" = /* ]]; then value=$(cygpath -m "$value"); fi; values+=("$value"); done;' if os.name == 'nt' else 'local values=("$@");'
        functions = '\n'.join(f'{name}() {{ {conversion} {invocation} --adapter {fixture_root} {name} "${{values[@]}}"; }}\nexport -f {name}' for name in ('ip', 'iptables', 'conntrack', 'sysctl', 'ethtool', 'systemctl', 'install'))
        guards = '\napt-get() { return 99; }; dnf() { return 99; }; yum() { return 99; }; timeout() { return 99; }; export -f apt-get dnf yum timeout\n'
        harness = functions + guards + f'\npython3() {{ {conversion} {invocation} --python {fixture_root} "${{values[@]}}"; }}\nexport -f python3\nbash ' + shlex.join([str(stage / 'install-v2.sh').replace('\\', '/'), *arguments[2:]]) + '\n'
        harness_path = self.root / 'harness.sh'
        harness_path.write_bytes(harness.encode('utf-8'))
        response = subprocess.run([BASH, harness_path.as_posix()], capture_output=True, text=True, timeout=40,
                                  env={**os.environ, 'MSYS_NO_PATHCONV': '1'})
        state = json.loads(state_path.read_text())
        self.active, self.enabled, self.ring, self.forwarding, self.rules = (state[key] for key in ('active', 'enabled', 'ring', 'forwarding', 'rules'))
        self.installer_commands = state['commands']
        self.installer_stdout, self.installer_stderr = response.stdout, response.stderr
        response.check_returncode()
        return response

    def command(self, *args, **kwargs):
        if args[0] == 'bash' and args[1].endswith('install-v2.sh'):
            self.calls.append(args)
            return self.install(args)
        return super().command(*args, **kwargs)


class InstallerIntegrationTests(unittest.TestCase):
    def test_fresh_install_interface_selection(self):
        for interface, failure, reason in (
            ('', None, None),
            ('', 'route', 'automatic_interface_unavailable'),
            ('missing0', None, 'invalid_outgoing_interface'),
        ):
            with self.subTest(interface=interface, failure=failure), tempfile.TemporaryDirectory() as directory:
                env = IntegratedEnvironment(Path(directory), failure=failure, active=False)
                for name in env.initial_files:
                    env.path(name).unlink()
                config = env.path('/etc/miga/config.json')
                arguments = ('bash', 'install-v2.sh', 'server.example', interface)
                if reason:
                    with self.assertRaises(subprocess.CalledProcessError):
                        env.install(arguments)
                    self.assertIn(reason, env.installer_stderr.splitlines())
                    self.assertFalse(any(command[0] == 'systemctl' for command in env.installer_commands))
                    self.assertFalse(config.exists())
                else:
                    env.install(arguments)
                    self.assertEqual(json.loads(config.read_text())['interface'], 'ens3')
                    self.assertIn(['ip', 'link', 'show', 'dev', 'ens3'], env.installer_commands)

    def test_actual_install_retains_stopped_service(self):
        with tempfile.TemporaryDirectory() as directory:
            env = IntegratedEnvironment(Path(directory), active=False)
            env.execute()
            self.assertFalse(env.active)
            self.assertEqual(env.enabled, 'disabled')
            self.assertEqual(json.loads(env.path('/etc/miga/config.json').read_text())['protocol'], 2)

    def test_actual_install_legacy_automatic_interface(self):
        for missing in (False, True):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as directory:
                env = IntegratedEnvironment(Path(directory))
                original = copy.deepcopy(migration.LEGACY)
                original['interface'] = ''
                if missing:
                    del original['interface']
                env.path('/etc/miga/config.json').write_text(json.dumps(original))
                env.execute()
                config = json.loads(env.path('/etc/miga/config.json').read_text())
                self.assertEqual(config['interface'], 'ens3')
                self.assertEqual(config['dns_server'], original['dns_server'])
                self.assertNotIn('encryption', config)
                backups = list(env.path('/var/backups').glob('miga-update-*/1'))
                self.assertTrue(any(json.loads(path.read_text()) == original for path in backups))

    def test_actual_install_legacy_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            env = IntegratedEnvironment(Path(directory))
            config = {'encryption': copy.deepcopy(migration.LEGACY['encryption'])}
            env.path('/etc/miga/config.json').write_text(json.dumps(config))
            env.execute()
            migrated = json.loads(env.path('/etc/miga/config.json').read_text())
            self.assertEqual(migrated['dns_server'], '')
            self.assertEqual(migrated['log_level'], 'none')
            self.assertEqual(migrated['interface'], 'ens3')
            self.assertEqual(migrated['control_ports'], [10000, 15000])

    def test_actual_install_success(self):
        with tempfile.TemporaryDirectory() as directory:
            env = IntegratedEnvironment(Path(directory))
            try:
                env.execute()
            except subprocess.CalledProcessError as error:
                self.fail(error.stderr)
            config = json.loads(env.path('/etc/miga/config.json').read_text())
            self.assertEqual(config['protocol'], 2)
            self.assertNotIn('encryption', config)
            self.assertTrue(env.active)
            self.assertEqual(env.enabled, 'disabled')
            self.assertIn('ExecStart=' + env.root.as_posix() + '/usr/local/miga_server --config', env.path('/etc/systemd/system/miga_server.service').read_text())
            self.assertTrue(env.path('/usr/local/libexec/miga-rx-ring').is_file())
            self.assertNotIn(migration.ICMP, env.rules['filter'])
            self.assertNotIn(migration.NAT, env.rules['nat'])
            self.assertIn(migration.SHARED_NAT, env.rules['nat'])

    def test_actual_install_failures_restore_snapshot(self):
        for failure in ('rx', 'binary', 'sysctl', 'start', 'icmp', 'ports', 'subnet'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                env = IntegratedEnvironment(Path(directory), failure=failure)
                with self.assertRaises(subprocess.CalledProcessError):
                    env.execute()
                self.assertTrue(env.installer_commands, env.installer_stderr)
                expected = {'rx': ['systemctl', 'restart', 'miga-rx-ring.service'],
                            'sysctl': ['sysctl', '-p', env.root.as_posix() + '/etc/sysctl.d/90-miga-v2.conf'],
                            'start': ['systemctl', 'start', migration.module.SERVICE],
                            'icmp': ['iptables', '-w', '5', '-t', 'filter', '-D', *migration.ICMP[1:]]}
                if failure in expected:
                    self.assertIn(expected[failure], env.installer_commands)
                elif failure == 'binary':
                    self.assertTrue(any(command[0] == 'install' and command[-1].endswith('/miga_server.v2.new') for command in env.installer_commands))
                else:
                    self.assertIn('control_port_conflict' if failure == 'ports' else 'virtual_subnet_conflict', env.installer_stderr)
                self.assertTrue(env.active)
                self.assertEqual(env.enabled, 'disabled')
                self.assertEqual(env.forwarding, '0')
                for name, data in env.initial_files.items():
                    self.assertEqual(env.path(name).read_bytes(), data, name)
                self.assertFalse(env.path('/var/lib/miga/new-secret').exists())
                self.assertEqual(env.rules, env.original_rules)
                self.assertIn('rollback=complete', env.stderr.getvalue())


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--adapter':
        response = adapter(Path(sys.argv[2]), sys.argv[3:])
        sys.stdout.write(response.stdout)
        raise SystemExit(response.returncode)
    if len(sys.argv) > 1 and sys.argv[1] == '--python':
        root = Path(sys.argv[2])
        sys.argv = sys.argv[3:]
        embedded_python(root)
    else:
        unittest.main()
