"""Quick scan: small places where threats arrive, and programs started at login."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backends.linux import LinuxBackend
from backends.windows import WindowsBackend
from core import quick_scan
from core.download_folders import DownloadFolder
from excludes import build_clamscan_exclude_args, path_is_excluded


class QuickScanTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.home = Path(self.directory.name)
        self.config = self.home / '.config'
        environment = patch.dict(os.environ, {'HOME': str(self.home), 'XDG_CONFIG_HOME': str(self.config),
                                              'XDG_DATA_HOME': str(self.home / '.local/share')})
        environment.start()
        self.addCleanup(environment.stop)
        self.backend = LinuxBackend()

    def make(self, relative, text=''):
        path = self.home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def test_linux_places_are_small_and_include_login_startup(self):
        for folder in ('Preuzimanja', 'Desktop', '.cache/mozilla', 'snap', '.config/google-chrome',
                       '.config/autostart', '.local/bin', '.local/share/applications'):
            (self.home / folder).mkdir(parents=True)
        # A translated Downloads folder comes from the user's folder settings.
        self.make('.config/user-dirs.dirs', 'XDG_DOWNLOAD_DIR="$HOME/Preuzimanja"\n')
        self.make('.bashrc')
        paths = self.backend.quick_scan_paths()
        for expected in ('Preuzimanja', 'Desktop', '.config/autostart', '.local/bin',
                         '.local/share/applications', '.bashrc'):
            self.assertIn(str(self.home / expected), paths)
        for large in ('.cache', '.cache/mozilla', 'snap', '.config/google-chrome', 'Downloads'):
            self.assertNotIn(str(self.home / large), paths)
        self.assertNotIn(str(self.home / '.zshrc'), paths)  # missing places are left out

    def test_programs_started_at_login_are_found_wherever_they_are(self):
        miner = self.make('.local/share/.hidden/miner')
        bot = self.make('bot.py')
        library = self.make('lib/helper.so')
        self.make('.config/autostart/miner.desktop',
                  f'[Desktop Entry]\nName=Update\nExec={miner} --quiet\n')
        self.make('.config/autostart/broken.desktop', 'Exec="unterminated\n')
        self.make('.config/systemd/user/bot.service',
                  f'[Service]\nExecStart=-/usr/bin/env python3 {bot}\nEnvironment=LD_PRELOAD={library}\n')
        with patch('backends.linux.shutil.which', return_value=None):
            programs = self.backend.autostart_programs()
        self.assertIn(str(miner), programs)
        self.assertIn(str(bot), programs)
        self.assertNotIn(str(library), programs)  # not a command

    def test_private_temporary_folders_of_services_are_skipped(self):
        patterns = self.backend.quick_scan_excludes()
        self.assertTrue(path_is_excluded('/tmp/systemd-private-abc-colord.service-x/tmp/f', patterns))
        self.assertTrue(path_is_excluded('/var/tmp/systemd-private-abc', patterns))
        self.assertFalse(path_is_excluded('/tmp/download.sh', patterns))
        self.assertEqual(build_clamscan_exclude_args(patterns), ['--exclude-dir=^/(var/)?tmp/systemd-private-[^/]+'])

    def test_targets_add_browser_folders_and_programs_but_never_the_whole_home(self):
        browser = self.home / 'Browser'
        browser.mkdir()
        program = self.make('.local/share/x/run')
        folders = [DownloadFolder(str(self.home), ('Firefox',)), DownloadFolder(str(browser), ('Chrome',))]
        with patch.object(quick_scan.backend, 'quick_scan_paths', return_value=['/tmp']), \
                patch.object(quick_scan.backend, 'autostart_programs', return_value=[str(program), '/gone']), \
                patch('core.quick_scan.discover_download_folders', return_value=folders):
            self.assertEqual(quick_scan.quick_scan_targets(), ['/tmp', str(browser), str(program)])

    def test_windows_run_entries_name_their_program_and_library(self):
        folder = self.home / 'Program Files' / 'Tool'
        folder.mkdir(parents=True)
        program = folder / 'tool.exe'
        program.write_text('')
        library = self.make('evil.dll')
        split = WindowsBackend.command_arguments
        self.assertEqual(split(f'"{program}" --tray'), [str(program), '--tray'])
        self.assertEqual(split(f'{program} --tray'), [str(program), '--tray'])  # unquoted, with spaces
        self.assertEqual(WindowsBackend.command_files(split(f'/no/rundll32.exe {library},Start')), [str(library)])


if __name__ == '__main__':
    unittest.main()
