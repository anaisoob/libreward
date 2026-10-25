import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from backends.linux import LinuxBackend
from backends.windows import WindowsBackend
from core.download_folders import discover_download_folders


class DownloadFolderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.downloads = self.root / 'Preuzimanja'
        self.downloads.mkdir()
        self.desktop = self.root / 'Desktop'
        self.desktop.mkdir()
        self.locations = []
        self.backend = SimpleNamespace(downloads_directory=lambda: self.downloads,
                                       desktop_directory=lambda: self.desktop,
                                       browser_profile_locations=lambda: self.locations)

    def chromium(self, name, profile, data):
        root = self.root / name
        path = root / profile / 'Preferences'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding='utf-8')
        self.locations.append((name, root, 'chromium'))
        return path

    def firefox(self, prefs):
        root = self.root / 'Firefox'
        profile = root / 'profile.custom'
        profile.mkdir(parents=True)
        (root / 'profiles.ini').write_text('[Profile0]\nIsRelative=1\nPath=profile.custom\n')
        (profile / 'prefs.js').write_text(prefs, encoding='utf-8')
        self.locations.append(('Firefox', root, 'firefox'))
        return profile

    def test_combines_shared_folder_sources_and_finds_custom_profile(self):
        custom = self.root / 'Browser files'
        custom.mkdir()
        self.chromium('Chrome', 'Default', {'download': {'default_directory': str(self.downloads)}})
        self.chromium('Edge', 'Profile 2', {'download': {'default_directory': str(custom)}})
        folders = discover_download_folders(self.backend)
        self.assertEqual(len(folders), 2)
        self.assertEqual(folders[0].path, str(self.downloads))
        self.assertIn('System Downloads', folders[0].sources)
        self.assertIn('Chrome — Default', folders[0].sources)
        self.assertEqual(folders[1].path, str(custom))

    def test_firefox_reads_unicode_custom_folder_and_user_override(self):
        custom = self.root / 'Preuzeto čć'
        custom.mkdir()
        profile = self.firefox('user_pref("browser.download.folderList", 2);\n'
                               'user_pref("browser.download.dir", ' + json.dumps(str(self.downloads)) + ');\n')
        (profile / 'user.js').write_text('user_pref("browser.download.dir", ' + json.dumps(str(custom)) + ');\n')
        folders = discover_download_folders(self.backend)
        self.assertEqual(folders[1].path, str(custom))
        self.assertIn('Firefox — profile.custom', folders[1].sources)

    def test_firefox_stale_custom_setting_does_not_override_system_mode(self):
        custom = self.root / 'old'
        custom.mkdir()
        self.firefox('user_pref("browser.download.folderList", 1);\n'
                     'user_pref("browser.download.dir", ' + json.dumps(str(custom)) + ');\n')
        self.assertEqual(len(discover_download_folders(self.backend)), 1)

    def test_firefox_desktop_mode(self):
        self.firefox('user_pref("browser.download.folderList", 0);\n')
        self.assertEqual(discover_download_folders(self.backend)[1].path, str(self.desktop))

    def test_firefox_absolute_profile_from_profiles_ini(self):
        profile = self.firefox('user_pref("browser.download.folderList", 0);\n')
        (profile.parent / 'profiles.ini').write_text('[Profile1]\nIsRelative=0\nPath=' + str(profile) + '\n')
        self.assertEqual(len(discover_download_folders(self.backend)), 2)

    def test_corrupt_and_relative_browser_settings_are_ignored(self):
        bad = self.chromium('Chrome', 'Default', {'download': {'default_directory': 'relative/path'}})
        self.chromium('Edge', 'Default', {'download': []})
        self.chromium('Brave', 'Default', [])
        self.assertEqual(len(discover_download_folders(self.backend)), 1)
        bad.write_text('{broken')
        self.assertEqual(len(discover_download_folders(self.backend)), 1)

    def test_empty_browser_preferences_use_system_downloads(self):
        self.chromium('Chrome', 'Default', {})
        folders = discover_download_folders(self.backend)
        self.assertEqual(len(folders), 1)
        self.assertIn('Chrome — Default', folders[0].sources)

    def test_missing_folders_are_not_suggested(self):
        self.chromium('Chrome', 'Default', {'download': {'default_directory': str(self.root / 'missing')}})
        self.backend.downloads_directory = lambda: None
        self.assertEqual(discover_download_folders(self.backend), [])

    def test_linux_respects_localized_xdg_download_directory_without_shell_execution(self):
        config = self.root / '.config'
        config.mkdir()
        (config / 'user-dirs.dirs').write_text('XDG_DOWNLOAD_DIR="$HOME/Preuzimanja"\n')
        with patch('backends.linux.Path.home', return_value=self.root), patch.dict(os.environ, {'XDG_CONFIG_HOME': str(config)}):
            self.assertEqual(LinuxBackend().downloads_directory(), self.downloads)
            (config / 'user-dirs.dirs').write_text('XDG_DOWNLOAD_DIR="$(touch /tmp/unwanted)/files"\n')
            self.assertEqual(LinuxBackend().downloads_directory(), self.root / 'Downloads')

    def test_linux_disabled_downloads_does_not_select_entire_home(self):
        config = self.root / '.config'
        config.mkdir()
        (config / 'user-dirs.dirs').write_text('XDG_DOWNLOAD_DIR="${HOME}"\n')
        with patch('backends.linux.Path.home', return_value=self.root), patch.dict(os.environ, {'XDG_CONFIG_HOME': str(config)}):
            self.assertIsNone(LinuxBackend().downloads_directory())

    def test_windows_uses_known_folder_for_redirected_downloads(self):
        with patch.object(WindowsBackend, '_known_folder', return_value=self.downloads) as known:
            self.assertEqual(WindowsBackend().downloads_directory(), self.downloads)
        known.assert_called_once_with('374de290-123f-4565-9164-39c4925e467b')

    def test_platform_profile_locations_respect_environment(self):
        with patch('backends.linux.Path.home', return_value=self.root), patch.dict(os.environ, {'XDG_CONFIG_HOME': str(self.root / 'cfg'), 'CHROME_CONFIG_HOME': str(self.root / 'chrome-cfg')}):
            locations = LinuxBackend().browser_profile_locations()
            self.assertIn(('Chrome', self.root / 'chrome-cfg/google-chrome', 'chromium'), locations)
            self.assertIn(('Edge', self.root / 'cfg/microsoft-edge', 'chromium'), locations)
        with patch.dict(os.environ, {'LOCALAPPDATA': str(self.root / 'local'), 'APPDATA': str(self.root / 'roaming')}):
            self.assertIn(('Chrome', self.root / 'local/Google/Chrome/User Data', 'chromium'), WindowsBackend().browser_profile_locations())
