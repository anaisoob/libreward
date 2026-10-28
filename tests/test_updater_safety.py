"""A changed update manifest must not be able to run programs on users' computers."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import updater

MANIFEST = json.loads((Path(__file__).resolve().parent.parent / 'updates/clamav-runtime-windows.json').read_text())
ENTRY = MANIFEST['platforms']['windows-x64']


class UpdaterSafetyTests(unittest.TestCase):
    def refused(self, change):
        entry = copy.deepcopy(ENTRY)
        change(entry)
        with patch.object(updater.backend, 'manages_own_runtime', return_value=True), \
                patch.object(updater, '_download_file', side_effect=AssertionError('downloaded')) as download:
            error = updater.perform_update(entry)
        download.assert_not_called()
        return str(error)

    def test_the_bundled_manifest_is_accepted(self):
        self.assertIsNone(updater._unsafe_entry(ENTRY))

    def test_downloads_come_only_from_official_clamav_releases(self):
        for url in ('https://evil.example/clamav.zip', 'http://github.com/Cisco-Talos/clamav/releases/download/x.zip',
                    'https://github.com/Cisco-Talos/clamav/releases/download/../../../attacker/x.zip',
                    'https://github.com/attacker/clamav/releases/download/v1/x.zip'):
            message = self.refused(lambda entry, url=url: entry['download'].update(url=url))
            self.assertIn('not an official ClamAV release', message)

    def test_unsafe_folder_or_missing_checksum_is_refused(self):
        self.assertIn('unsafe folder', self.refused(lambda entry: entry['download'].update(extract_dir='../../Users')))
        self.assertIn('SHA256', self.refused(lambda entry: entry['download'].update(sha256='')))

    def test_validation_never_runs_a_program_outside_the_runtime(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / 'ran'
            runtime = Path(folder) / 'runtime'
            runtime.mkdir()
            for command in (f'../../../../../../../usr/bin/touch {marker}', '..\\..\\Windows\\System32\\cmd.exe /c x'):
                with self.assertRaises(RuntimeError):
                    updater._validate_runtime(runtime, [command])
            self.assertFalse(marker.exists())
        self.assertEqual(updater.VALIDATION_COMMANDS, ('clamscan.exe --version', 'freshclam.exe --version'))


if __name__ == '__main__':
    unittest.main()
