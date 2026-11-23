import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch

source = (Path(__file__).resolve().parents[1] / 'install-v2.sh').read_text()
cleanup = source.split("<<'ICMP_CLEANUP'\n", 1)[1].split('\nICMP_CLEANUP', 1)[0]
compile(cleanup, 'installer-icmp-cleanup', 'exec')
legacy = '-A OUTPUT -p icmp -m icmp --icmp-type 3 -j DROP'
symbolic = '-A OUTPUT -p icmp --icmp-type destination-unreachable -j DROP'
other = '-A OUTPUT -d 192.0.2.1/32 -p icmp -m icmp --icmp-type 3 -j DROP'
port_only = '-A OUTPUT -p icmp -m icmp --icmp-type 3/3 -j DROP'
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    paths = {name: root / str(index) for index, name in enumerate(('/etc/iptables/rules.v4', '/etc/sysconfig/iptables'))}
    original = ('*filter\n' + legacy + '\n' + symbolic + '\n' + other + '\n' + port_only + '\nCOMMIT\n*raw\n' + legacy + '\nCOMMIT\n').encode()
    expected = ('*filter\n' + other + '\n' + port_only + '\nCOMMIT\n*raw\n' + legacy + '\nCOMMIT\n').encode()
    for path in paths.values():
        path.write_bytes(original)
    calls = []
    rules = [legacy, symbolic, legacy, other, port_only]

    def command(arguments, **kwargs):
        calls.append(arguments)
        assert kwargs['check'] and kwargs['timeout'] == 10
        if arguments[-2:] == ['-S', 'OUTPUT']:
            return subprocess.CompletedProcess(arguments, 0, '\n'.join(rules))
        assert arguments[:6] == ['iptables', '-w', '5', '-t', 'filter', '-D']
        rules.remove(' '.join(['-A'] + arguments[6:]))
        return subprocess.CompletedProcess(arguments, 0)

    def execute():
        with patch('pathlib.Path', side_effect=lambda name: paths[name]), patch('subprocess.run', side_effect=command), patch('os.fchown', create=True), contextlib.redirect_stdout(io.StringIO()):
            exec(compile(cleanup, 'installer-icmp-cleanup', 'exec'), {})

    execute()
    assert rules == [other, port_only]
    assert len(calls) == 4
    assert all(path.read_bytes() == expected for path in paths.values())
    calls.clear()
    execute()
    assert len(calls) == 1
    assert all(path.read_bytes() == expected for path in paths.values())
    for failure in ('-S', '-D'):
        for path in paths.values():
            path.write_bytes(original)
        def fail(arguments, **kwargs):
            if failure in arguments:
                raise subprocess.CalledProcessError(2, arguments)
            return subprocess.CompletedProcess(arguments, 0, legacy)
        with patch('pathlib.Path', side_effect=lambda name: paths[name]), patch('subprocess.run', side_effect=fail):
            try:
                exec(compile(cleanup, 'installer-icmp-cleanup', 'exec'), {})
                raise AssertionError('iptables failure ignored')
            except subprocess.CalledProcessError:
                pass
        assert all(path.read_bytes() == original for path in paths.values())
print('Installer ICMP cleanup: exact legacy rules, duplicates, persistence, unrelated rules, idempotence and failure propagation passed')
