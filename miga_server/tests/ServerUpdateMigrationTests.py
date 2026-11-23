import base64
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import MagicMock, patch


if os.name == 'nt':
    sys.modules.setdefault('fcntl', types.SimpleNamespace())
source = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('server_update', source / 'update-v2.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
LEGACY = {'client_ports': {'start': 30000, 'end': 31000}, 'interface': 'eth0', 'dns_server': '1.1.1.1',
          'log_level': 'warning', 'encryption': {'xor_key': base64.b64encode(bytes(range(128))).decode(),
                                              'swap_key': base64.b64encode(bytes(range(8))).decode()}}
ICMP = ['-A', 'OUTPUT', '-p', 'icmp', '-m', 'icmp', '--icmp-type', '3', '-j', 'DROP']
NAT = ['-A', 'POSTROUTING', '-s', '10.0.0.0/24', '!', '-o', 'tun_miga', '-j', 'MASQUERADE']
SHARED_NAT = ['-A', 'POSTROUTING', '-o', 'eth0', '-j', 'MASQUERADE']


class Environment:
    def __init__(self, root, failure=None, active=True):
        self.root = root
        self.failure = failure
        self.active = active
        self.enabled = 'disabled'
        self.ring = '512'
        self.forwarding = '0'
        self.calls = []
        self.fail_restore = False
        self.rules = {'filter': [['-P', 'OUTPUT', 'ACCEPT'], ICMP[:]],
                      'nat': [['-P', 'POSTROUTING', 'ACCEPT'], SHARED_NAT[:], NAT[:]]}
        self.original_rules = copy.deepcopy(self.rules)
        for name in module.FILES:
            if name == '/usr/local/bin/miga-server':
                continue
            path = self.path(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('old:' + name)
        self.path('/etc/miga/config.json').write_text(json.dumps(LEGACY))
        self.path('/usr/local/miga_server').write_text('1.2.5')
        self.path('/etc/systemd/system/miga_server.service').write_text('[Service]\nExecStart=/usr/local/miga_server\n')
        self.path('/proc/123').mkdir(parents=True)
        self.path('/proc/123/cmdline').write_bytes(b'/usr/local/miga_server\0')
        self.path('/var/lib/miga').mkdir(parents=True)
        self.path('/var/lib/miga/existing').write_text('retained')
        self.initial_files = {name: self.path(name).read_bytes() for name in module.FILES if self.path(name).is_file()}
        self.path('/var/backups').mkdir()

    def path(self, name):
        text = str(name)
        return self.root / text.lstrip('/') if text.startswith('/') and not text.startswith(str(self.root)) else Path(name)

    def command(self, *args, check=True, timeout=45):
        self.calls.append(args)
        result = ''
        code = 0
        if args[:2] == ('cp', '-a'):
            src, dst = map(Path, args[-2:])
            if self.fail_restore and dst.name == 'miga_server.miga-restore':
                raise subprocess.CalledProcessError(1, args)
            if src.is_dir():
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)
        elif args[0] == 'systemctl':
            operation = args[1]
            service = args[-1]
            if operation == 'is-enabled':
                result = self.enabled if service == module.SERVICE else 'enabled'
            elif operation == 'is-active':
                code = 0 if self.active else 3
            elif operation == 'show':
                result = '/etc/systemd/system/miga_server.service' if '--property=FragmentPath' in args else ('123' if '--property=MainPID' in args else ('no' if '--property=NeedDaemonReload' in args else ''))
            elif service == module.SERVICE:
                if operation == 'stop':
                    self.active = False
                    if ICMP in self.rules['filter']:
                        self.rules['filter'].remove(ICMP)
                    if self.failure == 'stop':
                        self.failure = None
                        raise subprocess.CalledProcessError(1, args)
                elif operation == 'start':
                    self.active = True
                    if self.path('/usr/local/miga_server').read_text() == '1.2.5':
                        self.rules['filter'].append(ICMP[:])
                elif operation in ('enable', 'disable'):
                    self.enabled = 'enabled' if operation == 'enable' else 'disabled'
            elif operation == 'start':
                self.ring = '4096'
        elif args[0] == 'ethtool':
            self.ring = args[-1]
        elif args[0] == 'sysctl':
            if args[1] == '-n':
                result = self.forwarding
            else:
                self.forwarding = args[-1].split('=')[-1]
        elif args[0] == 'iptables':
            table = args[4]
            operation = args[5]
            if operation == '-S':
                rules = self.rules[table]
                if len(args) > 6:
                    rules = [rule for rule in rules if rule[1] == args[6]]
                result = '\n'.join(' '.join(rule) for rule in rules)
            elif operation == '-D':
                self.rules[table].remove(['-A'] + list(args[6:]))
            elif operation == '-F':
                self.rules[table] = [rule for rule in self.rules[table] if rule[:2] != ['-A', args[6]]]
            elif operation == '-X':
                self.rules[table].remove(['-N', args[6]])
            elif operation in ('-N', '-A'):
                self.rules[table].append(list(args[5:]))
            elif operation == '-I':
                chain, position = args[6], int(args[7])
                indexes = [i for i, rule in enumerate(self.rules[table]) if rule[:2] == ['-A', chain]]
                index = indexes[position - 1] if position <= len(indexes) else len(self.rules[table])
                self.rules[table].insert(index, ['-A', chain] + list(args[8:]))
            else:
                raise AssertionError(args)
        elif args == ('ip', '-j', '-4', 'route', 'get', '1.1.1.1'):
            result = json.dumps([{'dev': 'ens3', 'type': 'unicast'}])
        elif args[:4] == ('ip', 'link', 'show', 'dev'):
            pass
        elif args[-1] == '--version':
            if args[0] == '/usr/local/miga_server':
                result = '1.2.5'
            elif candidate := os.environ.get('MIGA_TEST_SERVER_BINARY'):
                result = subprocess.check_output([candidate, '--version'], text=True).strip()
            else:
                result = json.loads((source / 'ServerVersion.inc').read_text())
        elif args[0] == 'bash' and args[1].endswith('prepare-dependencies.sh'):
            if self.failure == 'dependencies':
                return subprocess.CompletedProcess(args, 1, '', 'server_dependency_error manager=apt-get stage=install reason=package_command_failed code=1\nsecret_should_not_leak')
        elif args[0] == 'bash':
            for name in module.FILES:
                if name in module.PERSISTENCE:
                    continue
                path = self.path(name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('new:' + name)
            self.path('/etc/miga/config.json').write_text(json.dumps({'protocol': 2, 'interface': 'eth0'}))
            self.path('/var/lib/miga/existing').write_text('mutated')
            self.path('/var/lib/miga/new-secret').write_text('new')
            self.ring = '4096'
            self.forwarding = '1'
            self.active = True
            self.rules['filter'] += [['-N', 'MIGA_V2_UDP'], ['-A', 'INPUT', '-j', 'MIGA_V2_UDP'], ['-A', 'MIGA_V2_UDP', '-j', 'ACCEPT']]
            self.rules['filter'].append(['-A', 'OUTPUT', '-d', '192.0.2.1/32', '-j', 'ACCEPT'])
            if self.failure == 'install':
                raise subprocess.CalledProcessError(1, args)
            if self.failure == 'signal':
                raise RuntimeError('server_update_interrupted')
            if self.failure == 'timeout':
                raise subprocess.TimeoutExpired(args, timeout)
        else:
            raise AssertionError(args)
        response = subprocess.CompletedProcess(args, code, result, '')
        if check:
            response.check_returncode()
        return response

    def execute(self):
        chmod = os.chmod
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(module, 'Path', side_effect=self.path))
            stack.enter_context(patch.object(module, 'run', side_effect=self.command))
            stack.enter_context(patch.object(module.shutil, 'which', return_value='available'))
            stack.enter_context(patch.object(module, 'rings', return_value={'eth0': self.ring}))
            stack.enter_context(patch.object(module, 'ready', side_effect=RuntimeError('server_start_failed') if self.failure == 'ready' else None))
            stack.enter_context(patch.object(module, 'legacy_ready'))
            stack.enter_context(patch.object(module.os, 'readlink', return_value='/usr/local/miga_server'))
            stack.enter_context(patch.object(module.os, 'chmod', side_effect=lambda p, m, **k: chmod(self.path(p), m, **k)))
            stack.enter_context(patch.object(module.os, 'chown', create=True))
            mkdtemp = tempfile.mkdtemp
            stack.enter_context(patch.object(module.tempfile, 'mkdtemp', side_effect=lambda **k: mkdtemp(prefix=k['prefix'], dir=self.path(k['dir']))))
            self.stdout = io.StringIO()
            self.stderr = io.StringIO()
            stack.enter_context(contextlib.redirect_stdout(self.stdout))
            stack.enter_context(contextlib.redirect_stderr(self.stderr))
            module.update(source, 'example.test')


class MigrationTests(unittest.TestCase):
    def test_persistent_foreign_change_survives_rollback_as_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            env = Environment(Path(directory), failure='install')
            command = env.command
            def run(*args, **kwargs):
                try:
                    return command(*args, **kwargs)
                except subprocess.CalledProcessError:
                    if args[0] == 'bash' and args[1].endswith('install-v2.sh'):
                        env.path('/etc/iptables/rules.v4').write_text('*filter\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n')
                    raise
            env.command = run
            with self.assertRaises(subprocess.CalledProcessError):
                env.execute()
            self.assertIn('--dport 22', env.path('/etc/iptables/rules.v4').read_text())
            self.assertIn('reason=persistent_firewall_conflict', env.stderr.getvalue())
            self.assertIn('rollback=incomplete', env.stderr.getvalue())
            self.assertFalse(env.active)

    def test_unsupported_service_rejected_before_stop(self):
        cases = ('command', 'process', 'static', 'reload', 'override')
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                env = Environment(Path(directory))
                if case == 'command':
                    env.path('/etc/systemd/system/miga_server.service').write_text('[Service]\nExecStart=/usr/local/other\n')
                if case == 'process':
                    env.path('/proc/123/cmdline').write_bytes(b'/usr/local/miga_server\0--config\0/other\0')
                if case == 'static':
                    env.enabled = 'static'
                command = env.command
                def run(*args, **kwargs):
                    response = command(*args, **kwargs)
                    if case == 'reload' and '--property=NeedDaemonReload' in args:
                        response.stdout = 'yes'
                    if case == 'override' and '--property=DropInPaths' in args:
                        response.stdout = '/etc/systemd/system/miga_server.service.d/custom.conf'
                    return response
                env.command = run
                with self.assertRaises(ValueError):
                    env.execute()
                self.assertTrue(env.active)
                self.assertFalse(any(args[:2] == ('systemctl', 'stop') for args in env.calls))

    def test_state_backup_failure_never_runs_installer(self):
        with tempfile.TemporaryDirectory() as directory:
            env = Environment(Path(directory))
            command = env.command
            def run(*args, **kwargs):
                if args[:2] == ('cp', '-a') and args[-2].replace('\\', '/').endswith('/var/lib/miga'):
                    raise subprocess.CalledProcessError(1, args)
                return command(*args, **kwargs)
            env.command = run
            with self.assertRaises(subprocess.CalledProcessError):
                env.execute()
            self.assertTrue(env.active)
            self.assertFalse(any(args[0] == 'bash' and args[1].endswith('install-v2.sh') for args in env.calls))
            self.assertEqual(env.path('/var/lib/miga/existing').read_text(), 'retained')

    def test_directory_restore_copy_failure_preserves_current_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'state'
            target.mkdir()
            (target / 'current').write_text('retained-for-recovery')
            backup = module.Backup(root)
            backup.paths = [(target, root / 'saved', True)]
            with patch.object(module, 'run', side_effect=subprocess.CalledProcessError(1, [])), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaisesRegex(RuntimeError, 'backup_restore_failed'):
                    backup.restore()
            self.assertEqual((target / 'current').read_text(), 'retained-for-recovery')

    def test_dependency_failure_preserves_service(self):
        with tempfile.TemporaryDirectory() as directory:
            env = Environment(Path(directory), failure='dependencies')
            with self.assertRaisesRegex(RuntimeError, 'dependency_preparation_failed'):
                env.execute()
            self.assertTrue(env.active)
            self.assertEqual(len(env.calls), 1)
            self.assertIn('server_dependency_error manager=apt-get', env.stderr.getvalue())
            self.assertNotIn('secret_should_not_leak', env.stderr.getvalue())
            self.assertEqual(env.path('/usr/local/miga_server').read_text(), '1.2.5')

    def test_prepared_legacy_configuration(self):
        script = (source / 'install-v2.sh').read_text()
        preparation = script.split("<<'PY'\n", 1)[1].split('\nPY', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            env = Environment(Path(directory))
            for name in ('/proc/net/udp', '/proc/net/udp6'):
                path = env.path(name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('header\n')
            prepared = Path(directory) / 'prepared.json'
            def fixture_path(value):
                return source if value == str(source) else env.path(value)
            def output(args, **kwargs):
                return b'[]'
            with patch('sys.argv', ['-', 'public.example', 'eth0', str(prepared), '--legacy-1.2.5', str(source)]), patch('pathlib.Path', side_effect=fixture_path), patch('subprocess.check_output', side_effect=output), patch('subprocess.run', return_value=subprocess.CompletedProcess([], 3)):
                exec(compile(preparation, 'installer-config-preparation', 'exec'), {})
            value = json.loads(prepared.read_text())
            self.assertEqual(value['protocol'], 2)
            self.assertEqual(value['host'], 'public.example')
            self.assertEqual(value['interface'], LEGACY['interface'])
            self.assertEqual(value['dns_server'], LEGACY['dns_server'])
            self.assertEqual(value['log_level'], LEGACY['log_level'])
            self.assertEqual(value['control_ports'], [10000, 15000])
            self.assertEqual(value['virtual_subnet'], '10.64.0.0/16')
            self.assertNotIn('encryption', value)
            self.assertNotIn('client_ports', value)
            self.assertEqual(json.loads(env.path('/etc/miga/config.json').read_text()), LEGACY)

    def test_real_nat_cleanup_runtime_and_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            env = Environment(Path(directory))
            env.rules['nat'].append(NAT[:])
            v2 = '-A MIGA_V2_NAT -s 10.64.0.0/16 -o eth0 -j MASQUERADE'
            original = ('*nat\n' + ' '.join(NAT) + '\n' + ' '.join(NAT) + '\n' + ' '.join(SHARED_NAT) + '\n' + v2 + '\nCOMMIT\n').encode()
            expected = ('*nat\n' + ' '.join(SHARED_NAT) + '\n' + v2 + '\nCOMMIT\n').encode()
            for name in ('/etc/iptables/rules.v4', '/etc/sysconfig/iptables'):
                env.path(name).write_bytes(original)
            with patch.object(module, 'Path', side_effect=env.path), patch.object(module, 'run', side_effect=env.command), patch.object(module.os, 'fchown', create=True):
                module.remove_legacy_nat()
                module.remove_legacy_nat()
            self.assertNotIn(NAT, env.rules['nat'])
            self.assertIn(SHARED_NAT, env.rules['nat'])
            self.assertEqual(env.path('/etc/iptables/rules.v4').read_bytes(), expected)
            self.assertEqual(env.path('/etc/sysconfig/iptables').read_bytes(), expected)

    def test_v2_update_preserves_host_and_install_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            env = Environment(Path(directory))
            config = {'protocol': 2, 'interface': 'eth0', 'host': 'original.example', 'virtual_subnet': '10.64.0.0/16'}
            env.path('/etc/miga/config.json').write_text(json.dumps(config))
            env.path('/etc/systemd/system/miga_server.service').write_text('[Service]\nExecStart=/usr/local/miga_server --config /etc/miga/config.json\n')
            env.path('/proc/123/cmdline').write_bytes(b'/usr/local/miga_server\0--config\0/etc/miga/config.json\0')
            env.execute()
            installation = next(args for args in env.calls if args[0] == 'bash' and args[1].endswith('install-v2.sh'))
            self.assertEqual(installation[-3:], ('original.example', 'eth0', '--update-v2'))

    def test_restore_failure_reported_and_other_files_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            env = Environment(Path(directory), failure='install')
            env.fail_restore = True
            with self.assertRaises(subprocess.CalledProcessError):
                env.execute()
            self.assertIn('rollback=incomplete', env.stderr.getvalue())
            self.assertIn('server_update_restore_failed path=', env.stderr.getvalue())
            self.assertFalse(env.active)
            self.assertFalse(any(args[:2] == ('systemctl', 'start') and args[-1] == module.SERVICE for args in env.calls))
            self.assertEqual(env.path('/etc/miga/config.json').read_bytes(), env.initial_files['/etc/miga/config.json'])
            self.assertEqual(env.path('/etc/systemd/system/miga_server.service').read_bytes(), env.initial_files['/etc/systemd/system/miga_server.service'])

    def test_legacy_automatic_interface(self):
        for missing in (False, True):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as directory:
                env = Environment(Path(directory))
                config = copy.deepcopy(LEGACY)
                config['interface'] = ''
                if missing:
                    del config['interface']
                env.path('/etc/miga/config.json').write_text(json.dumps(config))
                env.execute()
                lookup = ('ip', '-j', '-4', 'route', 'get', '1.1.1.1')
                installation = next(args for args in env.calls if args[0] == 'bash' and args[1].endswith('install-v2.sh'))
                self.assertEqual(installation[-2:], ('ens3', '--legacy-1.2.5'))
                self.assertLess(env.calls.index(lookup), env.calls.index(('systemctl', 'stop', module.SERVICE)))

    def test_automatic_interface_lookup_failure_preserves_service(self):
        with tempfile.TemporaryDirectory() as directory:
            env = Environment(Path(directory))
            config = copy.deepcopy(LEGACY)
            config['interface'] = ''
            env.path('/etc/miga/config.json').write_text(json.dumps(config))
            command = env.command
            def fail_lookup(*args, **kwargs):
                if args == ('ip', '-j', '-4', 'route', 'get', '1.1.1.1'):
                    raise subprocess.CalledProcessError(2, args)
                return command(*args, **kwargs)
            env.command = fail_lookup
            with self.assertRaises(subprocess.CalledProcessError):
                env.execute()
            self.assertTrue(env.active)
            self.assertFalse(any(args[:2] == ('systemctl', 'stop') for args in env.calls))
            self.assertEqual(json.loads(env.path('/etc/miga/config.json').read_text()), config)

    def test_automatic_interface_invalid_routes(self):
        for routes in ([], [{}, {}], [{'dev': 'lo'}], [{'dev': 'tun_miga'}], [{'dev': 'bad name'}], [{'dev': 'ens3', 'type': 'blackhole'}], [{'dev': None}]):
            with self.subTest(routes=routes):
                with patch.object(module, 'run', return_value=subprocess.CompletedProcess([], 0, json.dumps(routes))) as command:
                    with self.assertRaises(ValueError):
                        module.outgoing_interface({'interface': ''})
                    self.assertEqual(command.call_count, 1)
        with patch.object(module, 'run', side_effect=subprocess.CalledProcessError(1, [])):
            with self.assertRaises(subprocess.CalledProcessError):
                module.outgoing_interface({'interface': 'ens3'})
        for config in ({'protocol': 2, 'interface': ''}, {'protocol': 2}, {'interface': None}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                module.configuration(config)

    def test_legacy_validation(self):
        self.assertTrue(module.configuration(copy.deepcopy(LEGACY)))
        for edit in ({'protocol': 3}, {'protocol': None}, {'protocol': True}, {'extra': 1}, {'encryption': {}}, {'dns_server': True}, {'dns_server': 1}, {'client_ports': {'start': 1, 'end': 65536}}):
            value = copy.deepcopy(LEGACY)
            value.update(edit)
            with self.assertRaises((ValueError, TypeError)):
                module.configuration(value)

    def test_rule_ownership(self):
        self.assertTrue(module.owned('nat', NAT))
        self.assertTrue(module.owned('filter', ICMP))
        self.assertFalse(module.owned('nat', SHARED_NAT))
        self.assertFalse(module.owned('filter', ['-A', 'OUTPUT', '-d', '192.0.2.1/32'] + ICMP[2:]))

    def test_success_and_stopped_service(self):
        for active in (True, False):
            with self.subTest(active=active), tempfile.TemporaryDirectory() as directory:
                env = Environment(Path(directory), active=active)
                with patch.object(module, 'remove_legacy_nat', side_effect=lambda: env.rules['nat'].remove(NAT)):
                    env.execute()
                self.assertEqual(env.active, active)
                self.assertEqual(env.enabled, 'disabled')
                self.assertEqual(env.ring, '4096')
                self.assertNotIn(NAT, env.rules['nat'])
                self.assertIn(SHARED_NAT, env.rules['nat'])
                self.assertEqual(len(list(env.path('/var/backups').iterdir())), 1)
                self.assertTrue(any(args[-1] == '--legacy-1.2.5' for args in env.calls))

    def test_rollback_after_install_readiness_and_partial_stop(self):
        for failure in ('install', 'ready', 'stop', 'signal', 'timeout'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                env = Environment(Path(directory), failure=failure)
                with self.assertRaises((subprocess.CalledProcessError, RuntimeError, subprocess.TimeoutExpired)):
                    with patch.object(module, 'remove_legacy_nat', side_effect=lambda: env.rules['nat'].remove(NAT)):
                        env.execute()
                self.assertTrue(env.active)
                self.assertEqual(env.ring, '512')
                self.assertEqual(env.forwarding, '0')
                self.assertEqual(env.enabled, 'disabled')
                for name, original in env.initial_files.items():
                    self.assertEqual(env.path(name).read_bytes(), original)
                self.assertEqual(env.path('/var/lib/miga/existing').read_text(), 'retained')
                self.assertFalse(env.path('/var/lib/miga/new-secret').exists())
                self.assertEqual(env.rules['filter'].count(ICMP), 1)
                self.assertFalse(any('MIGA_V2' in ' '.join(rule) for rule in env.rules['filter']))
                self.assertIn(SHARED_NAT, env.rules['nat'])
                self.assertIn(NAT, env.rules['nat'])
                if failure != 'stop':
                    self.assertIn(['-A', 'OUTPUT', '-d', '192.0.2.1/32', '-j', 'ACCEPT'], env.rules['filter'])


class ReadinessTests(unittest.TestCase):
    def execute(self, processes, responses, legacy=False, active=True):
        clock = [0]
        pids = iter(processes)
        messages = iter(responses)
        calls = []
        def run(*args, **kwargs):
            calls.append(args)
            if args[1] == 'show':
                output = next(pids, '123')
                code = 0
            else:
                output, code = '', 0 if active else 3
            return subprocess.CompletedProcess(args, code, output, '')
        probe = MagicMock()
        probe.__enter__.return_value = probe
        def receive(*args):
            message = next(messages, b'{"max_sessions":64}')
            if isinstance(message, BaseException):
                raise message
            return message
        probe.recv.side_effect = receive
        def sleep(seconds):
            clock[0] += seconds
        with patch.object(module, 'run', side_effect=run), patch.object(module.os, 'readlink', return_value='/usr/local/miga_server'), patch.object(module.socket, 'AF_UNIX', 1, create=True), patch.object(module.socket, 'SOCK_SEQPACKET', 5, create=True), patch.object(module.socket, 'socket', return_value=probe), patch.object(module.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(module.time, 'sleep', side_effect=sleep), patch.object(module, 'firewall_snapshot', side_effect=lambda: {'filter': next(messages, [ICMP[:]])}):
            (module.legacy_ready if legacy else module.ready)()
        return calls, probe

    def test_ready_requires_four_replies_from_same_pid(self):
        calls, probe = self.execute(['100', '100', '101', '101', '101', '101'], [b'{"max_sessions":64}'] * 6)
        self.assertEqual(sum(args[1] == 'show' for args in calls), 6)
        self.assertEqual(probe.sendall.call_count, 6)
        probe.sendall.assert_called_with(b'{"scope":"settings","operation":"get"}')

    def test_ready_retries_invalid_json_and_socket_errors(self):
        calls, probe = self.execute(['123'] * 6, [b'bad', OSError('not-ready')] + [b'{"max_sessions":64}'] * 4)
        self.assertEqual(probe.recv.call_count, 6)

    def test_ready_rejects_late_death_and_timeout(self):
        with self.assertRaisesRegex(RuntimeError, 'server_start_failed'):
            self.execute(['123', '123', '0'], [b'{"max_sessions":64}'] * 3)
        with self.assertRaisesRegex(RuntimeError, 'server_readiness_timeout'):
            self.execute(['123'] * 30, [b'{}'] * 30)

    def test_legacy_waits_for_startup_rule_and_stable_pid(self):
        calls, _ = self.execute(['100', '100', '101', '101', '101', '101'], [[], [ICMP[:]], [ICMP[:]], [ICMP[:]], [ICMP[:]], [ICMP[:]]], legacy=True)
        self.assertEqual(sum(args[1] == 'show' for args in calls), 6)

    def test_run_kills_child_group_on_timeout_or_signal(self):
        for error in (subprocess.TimeoutExpired('fixture', 1), RuntimeError('server_update_interrupted')):
            with self.subTest(error=type(error).__name__):
                process = MagicMock(pid=456)
                process.__enter__.return_value = process
                process.communicate.side_effect = [error, ('', '')]
                with patch.object(module.subprocess, 'Popen', return_value=process) as popen, patch.object(module.os, 'killpg', create=True) as kill, patch.object(module.signal, 'SIGKILL', 9, create=True):
                    with self.assertRaises(type(error)):
                        module.run('fixture', timeout=1)
                self.assertTrue(popen.call_args.kwargs['start_new_session'])
                kill.assert_called_once_with(456, 9)


if __name__ == '__main__':
    unittest.main()
