"""Exercises install.sh, and install.ps1 under PowerShell 7 (pwsh), in a scratch filesystem with
fake downloads, services and supervisor.

    python3 -m unittest discover -s deploy -p 'test_*.py'
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
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
    print({'-s': os.environ.get('MOCK_OS', 'Linux'), '-m': 'x86_64'}[args[0]])
elif name in ('apt-get', 'pacman'):
    # The index is stale until refreshed: it names a package the mirror no longer has, as a
    # computer's often does. Refreshed, the package brings bwrap with it.
    refresh = args[0] == 'update' if name == 'apt-get' else args[0] == '-Sy'
    if refresh:
        (root / f'{name}-refreshed').touch()
        if os.environ.get('MOCK_REFRESH_FAILS'):
            print('E: The repository https://broken.example noble Release does not have a Release file.',
                  file=sys.stderr)
            sys.exit(100)
    if args[0] == 'update':
        sys.exit(0)
    if os.environ.get('MOCK_PACKAGE_BROKEN') or not (root / f'{name}-refreshed').exists():
        print('E: Failed to fetch http://archive.example/pool/main/b/bubblewrap/bubblewrap_0.9.0_amd64.deb'
              '  404  Not Found', file=sys.stderr)
        sys.exit(100)
    print('Setting up bubblewrap (0.9.0) ...')
    shutil.copyfile(sys.argv[0], root / 'stubs' / 'bwrap')
    (root / 'stubs' / 'bwrap').chmod(0o755)
elif name == 'curl':
    shutil.copyfile(root / 'release' / args[-1].rsplit('/', 1)[-1], args[args.index('-o') + 1])
elif name in ('minisign', 'minisign.exe'):
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
if sys.argv[1:3] == ['system', 'enable'] and os.environ.get('MOCK_SYSTEM_REFUSED'):
    print('happy-supervisor: /opt is writable by others', file=sys.stderr)
    sys.exit(1)
if sys.argv[1] == 'join':
    out = (root / 'events').open('a')
    out.write(json.dumps(['join token', os.environ.get('HAPPY_JOIN_TOKEN')]) + '\n')
    out.close()
    state = pathlib.Path(sys.argv[sys.argv.index('--state-dir') + 1])
    (state / 'private').mkdir(parents=True)
    (state / 'private' / 'credentials.json').write_text('{}')
'''

# happy-supervisor-boot: `install --from` stores the supervisor the installer downloaded as current
# and prints its path, downloading nothing; `exec` runs the current one.
BOOT = r'''#!/usr/bin/python3
import json, os, pathlib, shutil, sys
root = pathlib.Path(os.environ['MOCK_ROOT'])
args = sys.argv[1:]
with (root / 'events').open('a') as out:
    out.write(json.dumps(['boot', *args]) + '\n')
boot_dir = pathlib.Path(args[args.index('--dir') + 1])
if args[0] == 'install':
    version = args[args.index('--version') + 1]
    source = pathlib.Path(args[args.index('--from') + 1])
    for name in ['SHA256SUMS', 'SHA256SUMS.minisig']:
        assert (source / name).exists(), name
    target = boot_dir / 'versions' / version / 'happy-supervisor'
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source / os.environ.get('MOCK_FILE', 'happy-supervisor-linux-x86_64'), target)
    target.chmod(0o755)
    (boot_dir / 'state.json').write_text(json.dumps({'current': version, 'previous': None}))
    print(target)
elif args[0] == 'exec':
    current = json.loads((boot_dir / 'state.json').read_text())['current']
    binary = boot_dir / 'versions' / current / 'happy-supervisor'
    os.execv(binary, [str(binary), *args[args.index('--') + 1:]])
'''

JOIN = ['join', '--url', 'https://cp.example/api/nodes/join']
BASE = 'https://release.example'


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(os.path.realpath(self.scratch.name))
        self.bin = self.root / 'bin/happy-supervisor'
        self.boot = self.root / 'bin/happy-supervisor-boot'
        self.boot_dir = self.root / 'lib/happy-supervisor'
        self.state = self.root / 'state'
        self.unit = self.root / 'happy-supervisor.service'
        self.profile = self.root / 'apparmor-profile'
        self.stub = self.root / 'stubs'
        self.stub.mkdir()
        self.stubs('id', 'uname', 'curl', 'minisign', 'systemctl', 'loginctl', 'useradd', 'cat',
                   'apparmor_parser', 'bwrap', 'pkill', 'launchctl')
        release = self.root / 'release'
        release.mkdir()
        self.candidate = release / 'happy-supervisor-linux-x86_64'
        self.candidate.write_text(CANDIDATE)
        boot = release / 'happy-supervisor-boot-linux-x86_64'
        boot.write_text(BOOT)
        (release / 'SHA256SUMS').write_text(''.join(
            f'{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}\n' for f in (self.candidate, boot)))
        (release / 'SHA256SUMS.minisig').write_text('checked by the fake minisign')
        (release / 'latest').write_text('0.2.0-linux.1\n')
        systemd = self.root / 'systemd'
        systemd.mkdir()
        source = Path(__file__).with_name('install.sh').read_text()
        for original, replacement in {
            'BIN=/usr/local/bin/happy-supervisor\n': f'BIN={self.bin}\n',
            'BOOT=/usr/local/bin/happy-supervisor-boot': f'BOOT={self.boot}',
            'BOOT_DIR=/usr/local/lib/happy-supervisor': f'BOOT_DIR={self.boot_dir}',
            'STATE=/var/lib/happy-supervisor': f'STATE={self.state}',
            'UNIT=/etc/systemd/system/happy-supervisor.service': f'UNIT={self.unit}',
            'APPARMOR_PROFILE=/etc/apparmor.d/happy-supervisor-bwrap': f'APPARMOR_PROFILE={self.profile}',
            'SYSTEM_DIR=/opt/happy-system': f'SYSTEM_DIR={self.root}/opt-happy-system',
            'SYSTEM_PROFILE=/etc/profile.d/happy-system.sh': f'SYSTEM_PROFILE={self.root}/profile-happy-system.sh',
            'DENY_FILES="/etc/cron.deny /etc/at.deny"':
                f'DENY_FILES="{self.root}/cron.deny {self.root}/at.deny"',
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
                    'HAPPY_INSTALL_BASE': BASE}

    def wrapper(self, boot=None, boot_dir=None):
        return ('#!/bin/sh\n'
                '# happy-supervisor as the service runs it: the current version under happy-supervisor-boot,\n'
                '# verified before it runs (docs/boot.md). Written by install.sh.\n'
                f'exec "{boot or self.boot}" exec --dir "{boot_dir or self.boot_dir}" -- "$@"\n')

    def stubs(self, *names):
        for name in names:
            command = self.stub / name
            command.write_text(MOCK)
            command.chmod(0o755)

    def fresh(self, **env):
        self.env.update(HAPPY_JOIN_URL='https://cp.example/api/nodes/join',
                        HAPPY_JOIN_TOKEN='test-only-token', **env)

    def boot_install(self, events):
        """The one `boot install`, with the directory it was given the downloads in."""
        [install] = [e for e in events if e[:2] == ['boot', 'install']]
        self.assertEqual(install[:-2], ['boot', 'install', '--dir', str(self.boot_dir),
                                        '--version', '0.2.0-linux.1'])
        self.assertEqual(install[-2], '--from')
        return install

    def assert_downloaded_both(self, events, platform='linux-x86_64'):
        fetched = [e[-1] for e in events if e[0] == 'curl']
        for name in [f'happy-supervisor-boot-{platform}', f'happy-supervisor-{platform}']:
            self.assertIn(f'{BASE}/releases/0.2.0-linux.1/{name}', fetched)

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
        # Both binaries came from the release; boot stored the supervisor as current without a
        # download of its own, and happy-supervisor runs what boot runs.
        self.assert_downloaded_both(events)
        self.boot_install(events)
        self.assertEqual((self.boot_dir / 'versions/0.2.0-linux.1/happy-supervisor').read_text(), CANDIDATE)
        self.assertEqual(json.loads((self.boot_dir / 'state.json').read_text()),
                         {'current': '0.2.0-linux.1', 'previous': None})
        self.assertEqual(self.boot.read_text(), BOOT)
        self.assertEqual(self.bin.read_text(), self.wrapper())
        # The join ran the stored supervisor, through the wrapper and boot.
        self.assertLess(events.index(self.boot_install(events)), events.index(['boot', 'exec', '--dir', str(self.boot_dir),
                                                                               '--', *JOIN, '--name', 'box',
                                                                               '--state-dir', str(self.state),
                                                                               '--workload-user', 'happy-workload']))
        unit = self.unit.read_text()
        self.assertIn(f'ExecStart="{self.boot}" run --dir "{self.boot_dir}" --base "{BASE}" -- '
                      f'run --state-dir "{self.state}" --workload-user happy-workload\n', unit)
        self.assertIn('WantedBy=multi-user.target', unit)
        self.assertIn('\nDelegate=yes\n', unit)
        self.assertEqual([e for e in events if e[0] == 'systemctl'],
                         [['systemctl', 'daemon-reload'], ['systemctl', 'enable', 'happy-supervisor'],
                          ['systemctl', 'restart', 'happy-supervisor']])
        self.assertFalse(self.profile.exists())
        self.assertIn('happy-supervisor 0.2.0-linux.1 is installed and running', self.output)

    def test_a_sudo_install_enables_system_access_after_joining(self):
        for flag in [(), ('--system',)]:
            with self.subTest(flag=flag):
                self.setUp()
                self.fresh()
                events = self.run_install(*flag)
                candidate = [e for e in events if e[0] == 'candidate']
                self.assertEqual(candidate[1], ['candidate', 'system', 'enable', '--state-dir', str(self.state)])
                self.assertEqual(candidate[0][1], 'join')
                self.assertLess(events.index(candidate[1]),
                                events.index(['systemctl', 'restart', 'happy-supervisor']))
                self.assertNotIn('note: system access is off', self.output)

    def test_an_upgrade_enables_system_access_before_stopping_the_service(self):
        self.fresh()
        self.run_install('--no-system')
        (self.root / 'events').unlink()
        del self.env['HAPPY_JOIN_TOKEN']
        events = self.run_install()
        enable = ['candidate', 'system', 'enable', '--state-dir', str(self.state)]
        self.assertLess(events.index(enable),
                        events.index(['systemctl', 'disable', '--now', 'happy-supervisor']))

    def test_no_system_leaves_system_access_off_on_install_and_upgrade(self):
        self.fresh()
        events = self.run_install('--no-system')
        self.assertFalse(any(e[:2] == ['candidate', 'system'] for e in events))
        (self.root / 'events').unlink()
        del self.env['HAPPY_JOIN_TOKEN']
        events = self.run_install('--no-system')
        self.assertFalse(any(e[:2] == ['candidate', 'system'] for e in events))
        self.assertIn('happy-supervisor upgraded to', self.output)

    def test_a_refused_system_enable_says_why_and_the_install_goes_on(self):
        self.fresh(MOCK_SYSTEM_REFUSED='1')
        self.run_install()
        self.assertIn('/opt is writable by others', self.output)
        self.assertIn('note: system access is off (above); fix that, then run: '
                      f'sudo happy-supervisor system enable --state-dir "{self.state}"', self.output)
        self.assertIn('happy-supervisor 0.2.0-linux.1 is installed and running', self.output)

    def test_with_system_a_refused_system_enable_fails(self):
        self.fresh(MOCK_SYSTEM_REFUSED='1')
        events = self.run_install('--system', success=False)
        self.assertIn('could not enable system access', self.output)
        self.assertFalse(any(e[0] == 'systemctl' and 'restart' in e for e in events))

    def test_system_without_sudo_refuses_before_downloading(self):
        self.fresh(MOCK_UID='1000')
        events = self.run_install('--system', success=False)
        self.assertIn('--system needs a sudo install', self.output)
        self.assertFalse(any(e[0] == 'curl' for e in events))

    def test_a_user_install_has_no_system_access_and_says_so(self):
        self.fresh(MOCK_UID='1000')
        events = self.run_install()
        self.assertFalse(any(e[:2] == ['candidate', 'system'] for e in events))
        self.assertIn('note: without sudo there is no system access', self.output)

    def test_where_apparmor_restricts_user_namespaces_bubblewrap_gets_a_profile(self):
        self.fresh(MOCK_RESTRICTED='1')
        events = self.run_install()
        self.assertIn(f'profile happy-supervisor-bwrap {self.stub}/bwrap flags=(unconfined) {{\n  userns,\n}}',
                      self.profile.read_text())
        self.assertIn(['apparmor_parser', '-r', str(self.profile)], events)

    def test_missing_bubblewrap_comes_from_the_package_manager_after_a_refresh(self):
        (self.stub / 'bwrap').unlink()
        self.stubs('apt-get')
        self.fresh()
        events = self.run_install()
        install = ['apt-get', 'install', '-y', '-o', 'DPkg::Lock::Timeout=120', 'bubblewrap']
        # With a stale index the install alone fails (404): the index is refreshed first.
        self.assertLess(events.index(['apt-get', 'update', '-q']), events.index(install))
        self.assertNotIn('Setting up bubblewrap', self.output)
        self.assertIn('happy-supervisor 0.2.0-linux.1 is installed and running', self.output)

    def test_a_repository_that_fails_to_refresh_does_not_stop_the_install(self):
        (self.stub / 'bwrap').unlink()
        self.stubs('apt-get')
        self.fresh(MOCK_REFRESH_FAILS='1')
        self.run_install()
        self.assertIn('does not have a Release file', self.output)
        self.assertIn('note: apt-get update failed (above)', self.output)
        self.assertIn('happy-supervisor 0.2.0-linux.1 is installed and running', self.output)

    def test_a_package_that_cannot_be_installed_shows_why_and_installs_nothing(self):
        (self.stub / 'bwrap').unlink()
        self.stubs('apt-get')
        self.fresh(MOCK_PACKAGE_BROKEN='1')
        events = self.run_install(success=False)
        self.assertIn('bubblewrap_0.9.0_amd64.deb  404  Not Found', self.output)
        self.assertIn('happy-supervisor install: apt-get could not install bubblewrap (its output is above)',
                      self.output)
        self.assertFalse(any(e[0] in ('curl', 'boot', 'candidate') for e in events))
        self.assertFalse(self.bin.exists() or self.boot.exists())

    def test_pacman_syncs_a_stale_database_and_installs(self):
        (self.stub / 'bwrap').unlink()
        self.stubs('pacman')
        self.fresh()
        events = self.run_install()
        self.assertEqual([e for e in events if e[0] == 'pacman'],
                         [['pacman', '-S', '--noconfirm', '--needed', 'bubblewrap'],
                          ['pacman', '-Sy', '--noconfirm', '--needed', 'bubblewrap']])
        self.assertIn('happy-supervisor 0.2.0-linux.1 is installed and running', self.output)

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
        self.assertFalse(self.bin.exists() or self.boot.exists())
        self.assertFalse(any(e[0] in ('candidate', 'useradd') for e in events))

    def test_a_user_install_runs_as_the_user_without_a_workload_user(self):
        self.fresh(MOCK_UID='1000')
        events = self.run_install()
        home = self.root / 'home'
        state = home / '.local/state/happy-supervisor'
        self.assertIn(['candidate', *JOIN, '--state-dir', str(state)], events)
        self.assertFalse(any(e[0] == 'useradd' for e in events))
        unit = (home / '.config/systemd/user/happy-supervisor.service').read_text()
        boot, boot_dir = home / '.local/bin/happy-supervisor-boot', home / '.local/lib/happy-supervisor'
        self.assertIn(f'ExecStart="{boot}" run --dir "{boot_dir}" --base "{BASE}" -- run --state-dir "{state}"\n',
                      unit)
        self.assertEqual((home / '.local/bin/happy-supervisor').read_text(), self.wrapper(boot, boot_dir))
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
        # As a computer installed before boot: the binary itself, and a service that runs it.
        self.bin.write_text('old')
        self.unit.write_text(f'ExecStart="{self.bin}" run --state-dir "{self.state}"\n')
        del self.env['HAPPY_JOIN_TOKEN']
        events = self.run_install()
        self.assertEqual(self.bin.read_text(), self.wrapper())
        self.assertIn(f'ExecStart="{self.boot}" run --dir "{self.boot_dir}" --base "{BASE}" -- '
                      f'run --state-dir "{self.state}" --workload-user happy-workload\n', self.unit.read_text())
        self.assert_downloaded_both(events)
        self.assertLess(events.index(self.boot_install(events)),
                        events.index(['systemctl', 'disable', '--now', 'happy-supervisor']))
        self.assertEqual(json.loads((self.boot_dir / 'state.json').read_text())['current'], '0.2.0-linux.1')
        # It does not join again; a sudo upgrade enables system access.
        self.assertEqual([e for e in events if e[0] == 'candidate'],
                         [['candidate', 'system', 'enable', '--state-dir', str(self.state)]])
        self.assertIn(['systemctl', 'restart', 'happy-supervisor'], events)
        self.assertIn('happy-supervisor upgraded to 0.2.0-linux.1', self.output)

        self.env['HAPPY_JOIN_TOKEN'] = 'another'
        self.run_install(success=False)
        self.assertIn('this computer has already joined', self.output)

    def test_a_release_without_boot_is_refused_before_anything_is_installed(self):
        release = self.root / 'release'
        (release / 'SHA256SUMS').write_text(
            f'{hashlib.sha256(self.candidate.read_bytes()).hexdigest()}  {self.candidate.name}\n')
        self.fresh()
        events = self.run_install(success=False)
        self.assertIn('release 0.2.0-linux.1 has no happy-supervisor-boot', self.output)
        self.assertFalse(self.bin.exists() or self.boot.exists())
        self.assertFalse(any(e[0] in ('boot', 'candidate') for e in events))

    def test_a_supervisor_that_is_not_the_signed_build_installs_nothing(self):
        self.candidate.write_text(CANDIDATE + '# changed\n')
        self.fresh()
        events = self.run_install(success=False)
        self.assertIn('checksum mismatch for happy-supervisor-linux-x86_64', self.output)
        self.assertFalse(self.bin.exists() or self.boot.exists() or self.boot_dir.exists())
        self.assertFalse(any(e[0] in ('boot', 'candidate', 'useradd') for e in events))

    def test_a_release_without_this_platforms_supervisor_says_what_it_has(self):
        release = self.root / 'release'
        boot = release / 'happy-supervisor-boot-linux-x86_64'
        (release / 'SHA256SUMS').write_text(
            f'{hashlib.sha256(boot.read_bytes()).hexdigest()}  {boot.name}\n'
            f'{"0" * 64}  happy-supervisor-linux-aarch64\n')
        self.fresh()
        self.run_install(success=False)
        self.assertIn('release 0.2.0-linux.1 has no build for linux-x86_64; it has: linux-aarch64', self.output)
        self.assertFalse(self.bin.exists() or self.boot.exists())

    def test_a_macos_user_install_runs_boot_from_launchd(self):
        release = self.root / 'release'
        for name in ['happy-supervisor', 'happy-supervisor-boot']:
            (release / f'{name}-linux-x86_64').rename(release / f'{name}-macos-x86_64')
        (release / 'SHA256SUMS').write_text(''.join(
            f'{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}\n'
            for f in sorted(release.glob('happy-supervisor-*'))))
        self.fresh(MOCK_UID='1000', MOCK_OS='Darwin', MOCK_FILE='happy-supervisor-macos-x86_64')
        events = self.run_install()
        home = self.root / 'home'
        boot, self.boot_dir = home / '.local/bin/happy-supervisor-boot', home / '.local/lib/happy-supervisor'
        state = home / 'Library/Application Support/happy-supervisor'
        plist = home / 'Library/LaunchAgents/engineering.happy.supervisor.plist'
        self.assert_downloaded_both(events, 'macos-x86_64')
        self.boot_install(events)
        self.assertEqual((self.boot_dir / 'versions/0.2.0-linux.1/happy-supervisor').read_text(), CANDIDATE)
        self.assertIn(['candidate', *JOIN, '--state-dir', str(state)], events)
        self.assertIn(f'<array><string>{boot}</string><string>run</string><string>--dir</string>'
                      f'<string>{self.boot_dir}</string><string>--base</string><string>{BASE}</string>'
                      f'<string>--</string><string>run</string><string>--state-dir</string>'
                      f'<string>{state}</string></array>', plist.read_text())
        self.assertIn(['launchctl', 'load', '-w', str(plist)], events)

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
        self.assertFalse(self.boot.exists() or self.boot_dir.exists())
        self.assertIn(['systemctl', 'disable', '--now', 'happy-supervisor'], events)
        self.assertIn(['userdel', '-r', 'happy-workload'], events)

    def test_uninstall_removes_happy_system_its_prefix_and_its_cron_and_at_entries(self):
        self.fresh()
        self.run_install('--system')
        prefix = self.root / 'opt-happy-system/npm'
        prefix.mkdir(parents=True)
        (self.root / 'profile-happy-system.sh').write_text('PATH=...')
        (self.root / 'cron.deny').write_text('daemon\nhappy-system\n')
        (self.root / 'at.deny').write_text('happy-system\nnobody\n')
        self.stubs('userdel')
        events = self.run_install('--uninstall')
        self.assertLess(events.index(['pkill', '-KILL', '-u', 'happy-system']),
                        events.index(['userdel', '-r', 'happy-system']))
        self.assertFalse((self.root / 'opt-happy-system').exists())
        self.assertFalse((self.root / 'profile-happy-system.sh').exists())
        self.assertEqual((self.root / 'cron.deny').read_text(), 'daemon\n')
        self.assertEqual((self.root / 'at.deny').read_text(), 'nobody\n')


# install.ps1 under PowerShell 7 with Windows' cmdlets as functions, which PowerShell prefers to
# cmdlets: downloads come from the scratch release, the scheduled task is recorded.
PS_PRELUDE = r'''
$PSStyle.OutputRendering = 'PlainText'
function Log { Add-Content -Path "$env:MOCK_ROOT/events" -Value (ConvertTo-Json -Compress -InputObject @($args)) }
function Invoke-WebRequest([switch]$UseBasicParsing, [Parameter(Position = 0)]$Uri, $OutFile) {
    Log 'download' $Uri
    Copy-Item (Join-Path $env:MOCK_ROOT 'release' ($Uri -split '/')[-1]) $OutFile
}
function Invoke-RestMethod([switch]$UseBasicParsing, [Parameter(Position = 0)]$Uri) {
    Get-Content -Raw (Join-Path $env:MOCK_ROOT 'release' 'latest')
}
function Expand-Archive($Path, $DestinationPath) {
    $minisign = Join-Path $DestinationPath 'minisign-win64' 'x86_64' 'minisign.exe'
    New-Item -ItemType Directory -Force -Path (Split-Path $minisign) | Out-Null
    Copy-Item (Join-Path $env:MOCK_ROOT 'stubs' 'minisign') $minisign
}
function Get-ScheduledTask($TaskName, $ErrorAction) {
    if (Test-Path "$env:MOCK_ROOT/task.json") { 'task' }
}
function Stop-ScheduledTask($TaskName, $ErrorAction) { Log 'Stop-ScheduledTask' $TaskName }
function Unregister-ScheduledTask($TaskName, $Confirm, $ErrorAction) {
    Log 'Unregister-ScheduledTask' $TaskName
    Remove-Item -Force "$env:MOCK_ROOT/task.json" -ErrorAction SilentlyContinue
}
function New-ScheduledTaskAction($Execute, $Argument) { @{ Execute = $Execute; Argument = $Argument } }
function New-ScheduledTaskTrigger([switch]$AtLogOn, $User) { @{ User = $User } }
function New-ScheduledTaskSettingsSet { 'settings' }
function New-ScheduledTaskPrincipal($UserId, $LogonType, $RunLevel) { @{ UserId = $UserId; RunLevel = $RunLevel } }
function Register-ScheduledTask($TaskName, $Action, $Trigger, $Settings, $Principal, [switch]$Force) {
    Log 'Register-ScheduledTask' $TaskName $Action.Execute $Action.Argument $Principal.UserId $Principal.RunLevel
    Set-Content -Path "$env:MOCK_ROOT/task.json" -Value $TaskName
}
function Start-ScheduledTask($TaskName) { Log 'Start-ScheduledTask' $TaskName }
'''

# Windows' happy-supervisor-boot.exe: `install --from` stores the downloaded supervisor as current,
# `exec` runs the current one and exits with its code.
PS_BOOT = r'''#!/usr/bin/python3
import json, os, pathlib, shutil, subprocess, sys
root = pathlib.Path(os.environ['MOCK_ROOT'])
args = sys.argv[1:]
with (root / 'events').open('a') as out:
    out.write(json.dumps(['boot', *args]) + '\n')
boot_dir = pathlib.Path(args[args.index('--dir') + 1])
if args[0] == 'install':
    version = args[args.index('--version') + 1]
    source = pathlib.Path(args[args.index('--from') + 1])
    for name in ['SHA256SUMS', 'SHA256SUMS.minisig']:
        assert (source / name).exists(), name
    target = boot_dir / 'versions' / version / 'happy-supervisor.exe'
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source / 'happy-supervisor-windows-x86_64.exe', target)
    target.chmod(0o755)
    (boot_dir / 'state.json').write_text(json.dumps({'current': version, 'previous': None}))
    print(target)
elif args[0] == 'exec':
    current = json.loads((boot_dir / 'state.json').read_text())['current']
    binary = boot_dir / 'versions' / current / 'happy-supervisor.exe'
    sys.exit(subprocess.call([str(binary), *args[args.index('--') + 1:]]))
'''

PS_WINDOWS = 'S-1-5-21-1-2-3-1001'


@unittest.skipUnless(shutil.which('pwsh') or os.environ.get('CI'), 'needs PowerShell 7 (pwsh)')
class PowerShellInstallTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(os.path.realpath(self.scratch.name))
        self.stub = self.root / 'stubs'
        self.stub.mkdir()
        for name in ['minisign', 'icacls']:
            (self.stub / name).write_text(MOCK)
            (self.stub / name).chmod(0o755)
        release = self.root / 'release'
        release.mkdir()
        self.candidate = release / 'happy-supervisor-windows-x86_64.exe'
        self.candidate.write_text(CANDIDATE)
        boot = release / 'happy-supervisor-boot-windows-x86_64.exe'
        boot.write_text(PS_BOOT)
        for binary in (self.candidate, boot):
            binary.chmod(0o755)
        (release / 'SHA256SUMS').write_text(''.join(
            f'{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}\n' for f in (self.candidate, boot)))
        (release / 'SHA256SUMS.minisig').write_text('checked by the fake minisign')
        (release / 'latest').write_text('0.2.0-linux.1\n')
        archive = release / 'minisign-0.12-win64.zip'
        archive.write_text('the fake Expand-Archive brings the fake minisign')
        source = Path(__file__).with_name('install.ps1').read_text()
        pinned = re.search(r"\$minisignSha256 = '[0-9a-f]{64}'", source).group(0)
        for original, replacement in {
            pinned: f"$minisignSha256 = '{hashlib.sha256(archive.read_bytes()).hexdigest()}'",
            '$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())\n'
            'if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {':
                'if ($env:MOCK_NOT_ADMIN) {',
            '[Security.Principal.WindowsIdentity]::GetCurrent().User.Value': f"'{PS_WINDOWS}'",
            '[Security.Principal.WindowsIdentity]::GetCurrent().Name': "'BOX\\me'",
        }.items():
            assert source.count(original) == 1, original
            source = source.replace(original, replacement)
        self.installer = self.root / 'install.ps1'
        self.installer.write_text(PS_PRELUDE + source)
        self.program_files = self.root / 'Program Files'
        self.program_data = self.root / 'ProgramData'
        self.local = self.root / 'AppData/Local'
        for directory in (self.program_files, self.program_data, self.local):
            directory.mkdir(parents=True)
        self.dir = self.program_files / 'Happy'
        self.boot = self.dir / 'happy-supervisor-boot.exe'
        self.boot_dir = self.program_data / 'happy-supervisor/boot'
        self.state = self.local / 'happy-supervisor'
        self.env = {'PATH': f'{self.stub}:/usr/bin:/bin', 'HOME': str(self.root),
                    'MOCK_ROOT': str(self.root), 'TMPDIR': str(self.root),
                    'ProgramFiles': str(self.program_files), 'ProgramData': str(self.program_data),
                    'LOCALAPPDATA': str(self.local), 'PROCESSOR_ARCHITECTURE': 'AMD64',
                    'HAPPY_INSTALL_BASE': BASE, 'POWERSHELL_TELEMETRY_OPTOUT': '1'}

    def fresh(self, **env):
        self.env.update(HAPPY_JOIN_URL='https://cp.example/api/nodes/join',
                        HAPPY_JOIN_TOKEN='test-only-token', **env)

    def run_install(self, success=True):
        events = self.root / 'events'
        events.unlink(missing_ok=True)
        # As `irm … | iex` shows it: a failure is its message.
        run = (f"try {{ & '{self.installer}' }} "
               "catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }")
        result = subprocess.run(['pwsh', '-NoProfile', '-NonInteractive', '-Command', run],
                                env=self.env, capture_output=True, text=True, timeout=120)
        self.output = result.stdout + result.stderr
        self.assertEqual(result.returncode == 0, success, self.output)
        return [json.loads(line) for line in events.read_text().splitlines()] if events.exists() else []

    def exec(self, *args):
        return ['boot', 'exec', '--dir', str(self.boot_dir), '--', *args]

    def assert_runs_boot(self, events):
        self.assertEqual(self.boot.read_text(), PS_BOOT)
        self.assertEqual((self.boot_dir / 'versions/0.2.0-linux.1/happy-supervisor.exe').read_text(), CANDIDATE)
        self.assertEqual(json.loads((self.boot_dir / 'state.json').read_text())['current'], '0.2.0-linux.1')
        [install] = [e for e in events if e[:2] == ['boot', 'install']]
        self.assertEqual(install[:-1], ['boot', 'install', '--dir', str(self.boot_dir),
                                        '--version', '0.2.0-linux.1', '--from'])
        self.assertIn(['icacls', str(self.boot_dir), '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F',
                       '*S-1-5-32-544:(OI)(CI)F', f'*{PS_WINDOWS}:(OI)(CI)F', '*S-1-5-32-545:(OI)(CI)RX'], events)
        self.assertLess(events.index(install), events.index(self.exec('install-sandbox')))
        self.assertIn(['Register-ScheduledTask', 'happy-supervisor', str(self.boot),
                       f'run --dir "{self.boot_dir}" --base "{BASE}" -- run --state-dir "{self.state}"',
                       'BOX\\me', 'Limited'], events)
        self.assertEqual(events[-1], ['Start-ScheduledTask', 'happy-supervisor'])
        self.assertEqual((self.dir / 'happy-supervisor.cmd').read_text(),
                         f'@"{self.boot}" exec --dir "{self.boot_dir}" -- %*\n')
        self.assertFalse((self.dir / 'happy-supervisor.exe').exists())

    def test_an_install_downloads_both_binaries_and_runs_the_supervisor_under_boot(self):
        self.fresh(HAPPY_NODE_NAME='box')
        events = self.run_install()
        downloaded = [e[1] for e in events if e[0] == 'download']
        for name in ['happy-supervisor-boot-windows-x86_64.exe', 'happy-supervisor-windows-x86_64.exe']:
            self.assertIn(f'{BASE}/releases/0.2.0-linux.1/{name}', downloaded)
        self.assert_runs_boot(events)
        join = self.exec('join', '--url', 'https://cp.example/api/nodes/join', '--state-dir', str(self.state),
                         '--name', 'box')
        self.assertLess(events.index(self.exec('install-sandbox')), events.index(join))
        self.assertIn(['join token', 'test-only-token'], events)
        self.assertNotIn('test-only-token', [arg for event in events if event[0] in ('boot', 'candidate')
                                             for arg in event])
        self.assertIn('happy-supervisor 0.2.0-linux.1 is installed and running', self.output)

    def test_an_install_from_before_boot_moves_onto_boot_without_joining(self):
        # As a computer installed before boot: the supervisor in Program Files, joined.
        self.dir.mkdir()
        (self.dir / 'happy-supervisor.exe').write_text('old')
        (self.state / 'private').mkdir(parents=True)
        (self.state / 'private/credentials.json').write_text('{}')
        events = self.run_install()
        self.assert_runs_boot(events)
        self.assertFalse(any(e[:5] == self.exec('join') for e in events))
        self.assertIn('happy-supervisor upgraded to 0.2.0-linux.1', self.output)

        self.env['HAPPY_JOIN_TOKEN'] = 'another'
        self.run_install(success=False)
        self.assertIn('this computer has already joined', self.output)

    def test_a_supervisor_that_is_not_the_signed_build_installs_nothing(self):
        self.candidate.write_text(CANDIDATE + '# changed\n')
        self.fresh()
        events = self.run_install(success=False)
        self.assertIn('checksum mismatch for happy-supervisor-windows-x86_64.exe', self.output)
        self.assertFalse(self.dir.exists() or self.boot_dir.exists())
        self.assertFalse(any(e[0] in ('boot', 'candidate', 'Register-ScheduledTask') for e in events))

    def test_a_bad_signature_installs_nothing(self):
        self.fresh(MOCK_BAD_SIGNATURE='1')
        events = self.run_install(success=False)
        self.assertIn('SHA256SUMS is not signed by the release key', self.output)
        self.assertFalse(self.dir.exists() or self.boot_dir.exists())
        self.assertFalse(any(e[0] in ('boot', 'candidate') for e in events))

    def test_a_release_without_boot_is_refused(self):
        release = self.root / 'release'
        (release / 'SHA256SUMS').write_text(
            f'{hashlib.sha256(self.candidate.read_bytes()).hexdigest()}  {self.candidate.name}\n')
        self.fresh()
        self.run_install(success=False)
        self.assertIn('release 0.2.0-linux.1 has no happy-supervisor-boot', self.output)
        self.assertFalse(self.dir.exists())

    def test_it_refuses_without_elevation(self):
        self.fresh(MOCK_NOT_ADMIN='1')
        events = self.run_install(success=False)
        self.assertIn('run this in an elevated PowerShell', self.output)
        self.assertFalse(any(e[0] == 'download' for e in events))

    def test_uninstall_removes_the_sandbox_task_boot_and_state(self):
        self.fresh()
        self.run_install()
        self.env['HAPPY_UNINSTALL'] = '1'
        events = self.run_install()
        self.assertIn(self.exec('install-sandbox', '--uninstall'), events)
        self.assertIn(['Unregister-ScheduledTask', 'happy-supervisor'], events)
        self.assertEqual(list(self.dir.iterdir()), [])
        self.assertFalse(self.boot_dir.exists() or self.state.exists())
        self.assertIn('happy-supervisor uninstalled', self.output)


class ReleaseNotesTests(unittest.TestCase):
    def test_the_release_notes_cover_this_version(self):
        version = Path(__file__).with_name('VERSION').read_text().strip()
        notes = Path(__file__).with_name('README.md').read_text()
        self.assertTrue(f'\n* **{version}.** ' in notes, f'deploy/README.md has no notes for {version}')


if __name__ == '__main__':
    unittest.main()
