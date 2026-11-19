"""Exercises install.sh in a scratch filesystem with fake downloads, systemd and supervisor.

    python3 -m unittest discover -s deploy -p 'test_*.py'
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


MOCK = r'''#!/usr/bin/python3
import json, os, pathlib, shutil, subprocess, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
root = pathlib.Path(os.environ['MOCK_ROOT'])
with (root / 'events').open('a') as out:
    out.write(json.dumps([name, *args]) + '\n')
if name == 'id':
    if args == ['-u']:
        print(os.environ.get('MOCK_UID', '0'))
    elif args == ['-un']:
        print('me')
    elif os.environ.get('MOCK_NO_WORKLOAD'):
        sys.exit(1)
    else:
        print('999')
elif name == 'uname':
    print({'-s': 'Linux', '-m': 'x86_64'}[args[0]])
elif name == 'apt-get':
    # The package brings bwrap with it.
    shutil.copyfile(sys.argv[0], root / 'stubs' / 'bwrap')
    (root / 'stubs' / 'bwrap').chmod(0o755)
elif name == 'curl':
    shutil.copyfile(root / 'release' / args[-1].rsplit('/', 1)[-1], args[args.index('-o') + 1])
elif name == 'minisign':
    sys.exit(1 if os.environ.get('MOCK_BAD_SIGNATURE') else 0)
elif name == 'cat':
    if args == ['/proc/sys/kernel/apparmor_restrict_unprivileged_userns']:
        print(os.environ.get('MOCK_RESTRICTED', '0'))
    else:
        sys.exit(subprocess.call(['/usr/bin/cat', *args]))
'''

CANDIDATE = r'''#!/usr/bin/python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ['MOCK_ROOT'])
with (root / 'events').open('a') as out:
    out.write(json.dumps(['candidate', *sys.argv[1:]]) + '\n')
if sys.argv[1] == 'join':
    out = (root / 'events').open('a')
    out.write(json.dumps(['join token', os.environ.get('HAPPY_JOIN_TOKEN')]) + '\n')
    out.close()
    state = pathlib.Path(sys.argv[sys.argv.index('--state-dir') + 1])
    (state / 'private').mkdir(parents=True)
    (state / 'private' / 'credentials.json').write_text('{}')
'''

JOIN = ['join', '--url', 'https://cp.example/api/nodes/join']


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(os.path.realpath(self.scratch.name))
        self.bin = self.root / 'bin/happy-supervisor'
        self.state = self.root / 'state'
        self.unit = self.root / 'happy-supervisor.service'
        self.profile = self.root / 'apparmor-profile'
        self.stub = self.root / 'stubs'
        self.stub.mkdir()
        self.stubs('id', 'uname', 'curl', 'minisign', 'systemctl', 'loginctl', 'useradd', 'cat',
                   'apparmor_parser', 'bwrap')
        release = self.root / 'release'
        release.mkdir()
        self.candidate = release / 'happy-supervisor-linux-x86_64'
        self.candidate.write_text(CANDIDATE)
        digest = hashlib.sha256(self.candidate.read_bytes()).hexdigest()
        (release / 'SHA256SUMS').write_text(f'{digest}  {self.candidate.name}\n')
        (release / 'SHA256SUMS.minisig').write_text('checked by the fake minisign')
        (release / 'latest').write_text('0.2.0-linux.1\n')
        systemd = self.root / 'systemd'
        systemd.mkdir()
        source = Path(__file__).with_name('install.sh').read_text()
        for original, replacement in {
            'BIN=/usr/local/bin/happy-supervisor': f'BIN={self.bin}',
            'STATE=/var/lib/happy-supervisor': f'STATE={self.state}',
            'UNIT=/etc/systemd/system/happy-supervisor.service': f'UNIT={self.unit}',
            'APPARMOR_PROFILE=/etc/apparmor.d/happy-supervisor-bwrap': f'APPARMOR_PROFILE={self.profile}',
            '[ ! -d /run/systemd/system ]': f'[ ! -d {systemd} ]',
        }.items():
            assert source.count(original) == 1, original
            source = source.replace(original, replacement)
        self.installer = self.root / 'install.sh'
        self.installer.write_text(source)
        # The system's programs, less bubblewrap and every package manager.
        tools = self.root / 'tools'
        tools.mkdir()
        hidden = {'apt-get', 'dnf', 'apk', 'zypper', 'pacman', 'bwrap', 'minisign'}
        for directory in ['/bin', '/usr/bin']:
            for program in Path(directory).iterdir():
                link = tools / program.name
                if program.name not in hidden and not os.path.lexists(link):
                    link.symlink_to(program)
        self.env = {'PATH': f'{self.stub}:{tools}', 'HOME': str(self.root / 'home'),
                    'MOCK_ROOT': str(self.root), 'TMPDIR': str(self.root),
                    'HAPPY_INSTALL_BASE': 'https://release.example'}

    def stubs(self, *names):
        for name in names:
            command = self.stub / name
            command.write_text(MOCK)
            command.chmod(0o755)

    def fresh(self, **env):
        self.env.update(HAPPY_JOIN_URL='https://cp.example/api/nodes/join',
                        HAPPY_JOIN_TOKEN='test-only-token', **env)

    def run_install(self, *args, success=True):
        result = subprocess.run(['sh', str(self.installer), *args], env=self.env,
                                capture_output=True, text=True, timeout=60)
        self.output = result.stdout + result.stderr
        self.assertEqual(result.returncode == 0, success, self.output)
        events = self.root / 'events'
        return [json.loads(line) for line in events.read_text().splitlines()] if events.exists() else []

    def test_a_system_install_runs_its_work_as_happy_workload(self):
        self.fresh(HAPPY_NODE_NAME='box', MOCK_NO_WORKLOAD='1')
        events = self.run_install()
        self.assertIn(['useradd', '--system', '--create-home', '--home-dir', '/home/happy-workload',
                       '--shell', '/usr/sbin/nologin', 'happy-workload'], events)
        self.assertIn(['candidate', *JOIN, '--name', 'box', '--state-dir', str(self.state),
                       '--workload-user', 'happy-workload'], events)
        self.assertIn(['join token', 'test-only-token'], events)
        self.assertNotIn('test-only-token', [arg for event in events if event[0] == 'candidate'
                                             for arg in event])
        unit = self.unit.read_text()
        self.assertIn(f'ExecStart="{self.bin}" run --state-dir "{self.state}" --workload-user happy-workload\n',
                      unit)
        self.assertIn('WantedBy=multi-user.target', unit)
        self.assertIn('\nDelegate=yes\n', unit)
        self.assertEqual([e for e in events if e[0] == 'systemctl'],
                         [['systemctl', 'daemon-reload'], ['systemctl', 'enable', 'happy-supervisor'],
                          ['systemctl', 'restart', 'happy-supervisor']])
        self.assertFalse(self.profile.exists())
        self.assertIn('happy-supervisor 0.2.0-linux.1 is installed and running', self.output)

    def test_where_apparmor_restricts_user_namespaces_bubblewrap_gets_a_profile(self):
        self.fresh(MOCK_RESTRICTED='1')
        events = self.run_install()
        self.assertIn(f'profile happy-supervisor-bwrap {self.stub}/bwrap flags=(unconfined) {{\n  userns,\n}}',
                      self.profile.read_text())
        self.assertIn(['apparmor_parser', '-r', str(self.profile)], events)

    def test_missing_bubblewrap_comes_from_the_package_manager(self):
        (self.stub / 'bwrap').unlink()
        self.stubs('apt-get')
        self.fresh()
        events = self.run_install()
        self.assertIn(['apt-get', 'install', '-y', 'bubblewrap'], events)

    def test_without_bubblewrap_or_a_package_manager_it_refuses_before_downloading(self):
        (self.stub / 'bwrap').unlink()
        self.fresh()
        events = self.run_install(success=False)
        self.assertIn('no known package manager', self.output)
        self.assertFalse(any(e[0] == 'curl' for e in events))
        self.assertFalse(self.bin.exists())

    def test_a_bad_signature_installs_and_joins_nothing(self):
        self.fresh(MOCK_BAD_SIGNATURE='1')
        events = self.run_install(success=False)
        self.assertIn('SHA256SUMS is not signed by the release key', self.output)
        self.assertFalse(self.bin.exists())
        self.assertFalse(any(e[0] in ('candidate', 'useradd') for e in events))

    def test_a_user_install_runs_as_the_user_without_a_workload_user(self):
        self.fresh(MOCK_UID='1000')
        events = self.run_install()
        home = self.root / 'home'
        state = home / '.local/state/happy-supervisor'
        self.assertIn(['candidate', *JOIN, '--state-dir', str(state)], events)
        self.assertFalse(any(e[0] == 'useradd' for e in events))
        unit = (home / '.config/systemd/user/happy-supervisor.service').read_text()
        self.assertIn(f'ExecStart="{home}/.local/bin/happy-supervisor" run --state-dir "{state}"\n', unit)
        self.assertIn('WantedBy=default.target', unit)
        self.assertIn('\nDelegate=yes\n', unit)
        self.assertIn(['systemctl', '--user', 'restart', 'happy-supervisor'], events)
        self.assertIn(['loginctl', 'enable-linger', 'me'], events)

    def test_a_user_install_without_bubblewrap_refuses(self):
        (self.stub / 'bwrap').unlink()
        self.stubs('apt-get')
        self.fresh(MOCK_UID='1000')
        events = self.run_install(success=False)
        self.assertIn('an install without sudo cannot add', self.output)
        self.assertFalse(any(e[0] in ('apt-get', 'curl') for e in events))

    def test_running_it_again_upgrades_without_joining(self):
        self.fresh()
        self.run_install()
        (self.root / 'events').unlink()
        self.bin.write_text('old')
        del self.env['HAPPY_JOIN_TOKEN']
        events = self.run_install()
        self.assertEqual(self.bin.read_bytes(), self.candidate.read_bytes())
        self.assertFalse(any(e[0] == 'candidate' for e in events))
        self.assertIn(['systemctl', 'restart', 'happy-supervisor'], events)
        self.assertIn('happy-supervisor upgraded to 0.2.0-linux.1', self.output)

        self.env['HAPPY_JOIN_TOKEN'] = 'another'
        self.run_install(success=False)
        self.assertIn('this computer has already joined', self.output)

    def test_without_a_join_url_it_says_what_to_set(self):
        self.env.update(HAPPY_JOIN_TOKEN='test-only-token')
        self.run_install(success=False)
        self.assertIn('set HAPPY_JOIN_URL to the join URL the control plane gave you', self.output)

    def test_uninstall_removes_the_service_state_binary_and_user(self):
        self.fresh()
        self.run_install()
        self.stubs('userdel')
        events = self.run_install('--uninstall')
        self.assertFalse(self.bin.exists() or self.unit.exists() or self.state.exists())
        self.assertIn(['systemctl', 'disable', '--now', 'happy-supervisor'], events)
        self.assertIn(['userdel', '-r', 'happy-workload'], events)


class ReleaseNotesTests(unittest.TestCase):
    def test_the_release_notes_cover_this_version(self):
        version = Path(__file__).with_name('VERSION').read_text().strip()
        notes = Path(__file__).with_name('README.md').read_text()
        self.assertTrue(f'\n* **{version}.** ' in notes, f'deploy/README.md has no notes for {version}')


if __name__ == '__main__':
    unittest.main()
