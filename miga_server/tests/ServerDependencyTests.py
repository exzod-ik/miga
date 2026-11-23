import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1]
BASH = os.environ.get('MIGA_TEST_BASH', 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else 'bash')


class DependencyTests(unittest.TestCase):
    def execute(self, missing='', manager='apt-get', failure=0, systemd='systemd', verify=True, failure_stage='refresh'):
        harness = r"""
mock_missing=$1
selected=$2
failure=$3
platform=$4
verify=$5
failure_stage=$6
installed=0
command() {
    if [ "$1" != -v ]; then return 99; fi
    case "$2" in
        apt-get|dnf|yum) [ "$2" = "$selected" ]; return ;;
    esac
    if [[ " $mock_missing " = *" $2 "* ]] && [ "$installed" -eq 0 ]; then return 1; fi
    return 0
}
cat() { printf '%s\n' "$platform"; }
timeout() {
    printf 'mock_command'; printf ' <%s>' "$@"; printf '\n'
    [ "$DEBIAN_FRONTEND" = noninteractive ] && [ "$NEEDRESTART_MODE" = l ] || return 99
    if [[ " $* " = *" apt-get "* ]] && [[ " $* " = *" install "* ]]; then
        [[ " $* " = *" --no-remove "* ]] && [[ " $* " = *" --no-upgrade "* ]] && [[ " $* " = *" --no-install-recommends "* ]] || return 99
    fi
    if [[ " $* " = *" dnf "* ]] || [[ " $* " = *" yum "* ]]; then
        [[ " $* " = *" --setopt=install_weak_deps=False "* ]] || return 99
    fi
    if [ "$failure" -ne 0 ] && { [ "$failure_stage" = refresh ] || [[ " $* " = *" install "* ]]; }; then printf '%s\n' 'secret_proxy_password' >&2; return "$failure"; fi
    if [ "$verify" = 1 ]; then installed=1; fi
}
"""
        helper = (SOURCE / 'prepare-dependencies.sh').read_text(encoding='utf8').replace('[ "$EUID" -eq 0 ]', 'true')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test.sh'
            path.write_text(harness + helper, encoding='utf8', newline='\n')
            return subprocess.run([BASH, path.as_posix(), missing, manager, str(failure), systemd, str(int(verify)), failure_stage], capture_output=True, text=True, timeout=15)

    def test_existing_no_package_commands(self):
        result = self.execute(manager='none')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('installed=0', result.stdout)
        self.assertNotIn('mock_command', result.stdout)

    def test_missing_packages_all_managers(self):
        for manager in ('apt-get', 'dnf', 'yum'):
            with self.subTest(manager=manager):
                result = self.execute('python3 ip conntrack sysctl ethtool awk', manager)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('packages=python3 ' + ('iproute2 conntrack procps' if manager == 'apt-get' else 'iproute conntrack-tools procps-ng') + ' ethtool gawk', result.stdout)
                self.assertIn('installed=6', result.stdout)

    def test_failure_and_timeout_are_secret_safe(self):
        for code in (1, 124, 137):
            result = self.execute('conntrack', failure=code)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('stage=refresh reason=package_command_failed code=' + str(code), result.stderr)
            self.assertNotIn('secret_proxy_password', result.stdout + result.stderr)

    def test_install_failure_is_secret_safe(self):
        result = self.execute('conntrack', failure=100, failure_stage='install')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('stage=install reason=package_command_failed code=100', result.stderr)
        self.assertNotIn('secret_proxy_password', result.stdout + result.stderr)

    def test_unsupported_manager(self):
        result = self.execute('conntrack', manager='none')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unsupported_package_manager', result.stderr)

    def test_non_systemd_precedes_install(self):
        result = self.execute('conntrack', systemd='init')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('systemd_required', result.stderr)
        self.assertNotIn('server_dependencies_install', result.stdout)

    def test_post_install_verification(self):
        result = self.execute('conntrack', verify=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('stage=verify reason=missing_dependency_conntrack', result.stderr)

    def test_install_order_and_bounds(self):
        helper = (SOURCE / 'prepare-dependencies.sh').read_text(encoding='utf8')
        self.assertIn('execute refresh 120s', helper)
        self.assertIn('execute install 180s', helper)
        self.assertIn('--no-remove --no-upgrade', helper)
        for filename in ('install-v2.sh', 'update-v2.py'):
            script = (SOURCE / filename).read_text(encoding='utf8')
            self.assertLess(script.index('prepare-dependencies.sh'), script.index("systemctl', 'stop'" if filename.endswith('.py') else 'systemctl stop'))
        agent = (SOURCE.parent / 'MIGA Agent/ViewModels/ServerTabViewModel.cs').read_text(encoding='utf8')
        self.assertIn('bash prepare-dependencies.sh && python3 update-v2.py', agent)


if __name__ == '__main__':
    unittest.main()
