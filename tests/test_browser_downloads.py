"""Finished browser downloads read from copies of history databases."""
import json
import os
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from core.browser_downloads import (
    CHROMIUM_EPOCH_OFFSET,
    DownloadHistory,
    history_databases,
)


def chromium_profile(root, downloads):
    profile = Path(root) / 'Default'
    profile.mkdir(parents=True)
    with closing(sqlite3.connect(profile / 'History')) as db, db:
        db.execute('CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, end_time INTEGER, state INTEGER)')
        db.execute('CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT)')  # visited pages, never read
        db.executemany('INSERT INTO downloads (target_path, end_time, state) VALUES (?, ?, ?)',
                       [(path, int(finished * 1_000_000) + CHROMIUM_EPOCH_OFFSET, state)
                        for path, finished, state in downloads])
    return profile / 'History'


def firefox_profile(root, downloads):
    profile = Path(root) / 'abcd.default-release'
    profile.mkdir(parents=True)
    with closing(sqlite3.connect(profile / 'places.sqlite')) as db, db:
        db.execute('CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY, name TEXT)')
        db.execute('CREATE TABLE moz_annos (id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER, '
                   'content TEXT, lastModified INTEGER)')
        db.execute("INSERT INTO moz_anno_attributes VALUES (1, 'downloads/destinationFileURI'), "
                   "(2, 'downloads/metaData')")
        for place, (path, finished, state) in enumerate(downloads, 1):
            modified = int(finished * 1_000_000)
            db.execute('INSERT INTO moz_annos (place_id, anno_attribute_id, content, lastModified) VALUES (?, 1, ?, ?)',
                       (place, Path(path).as_uri(), modified))
            db.execute('INSERT INTO moz_annos (place_id, anno_attribute_id, content, lastModified) VALUES (?, 2, ?, ?)',
                       (place, json.dumps({'state': state, 'endTime': finished * 1000}), modified))
    return profile / 'places.sqlite'


class DownloadHistoryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.chrome, self.firefox = self.root / 'chrome', self.root / 'firefox'
        self.backend = SimpleNamespace(browser_profile_locations=lambda: [
            ('Chrome', self.chrome, 'chromium'), ('Firefox', self.firefox, 'firefox')])

    def test_finds_profiles_of_both_kinds(self):
        chromium_profile(self.chrome, [])
        firefox_profile(self.firefox, [])
        kinds = sorted(kind for kind, _path in history_databases(self.backend))
        self.assertEqual(kinds, ['chromium', 'firefox'])

    def test_profiles_in_new_locations_and_from_profiles_ini_are_found(self):
        from backends.linux import LinuxBackend
        with patch.dict(os.environ, {'XDG_CONFIG_HOME': str(self.root / 'config')}), \
                patch('backends.linux.Path.home', return_value=self.root / 'home'):
            roots = {str(root) for label, root, _kind in LinuxBackend().browser_profile_locations()
                     if label == 'LibreWolf'}
        self.assertIn(str(self.root / 'config/librewolf/librewolf'), roots)
        self.assertIn(str(self.root / 'home/.librewolf'), roots)
        # A profile somewhere else, named in profiles.ini.
        elsewhere = self.root / 'elsewhere-profile'
        firefox_profile(elsewhere.parent, [])
        (self.root / 'elsewhere-profile').mkdir(exist_ok=True)
        (self.root / 'elsewhere-profile' / 'places.sqlite').write_bytes(
            (self.root / 'abcd.default-release' / 'places.sqlite').read_bytes())
        self.firefox.mkdir()
        (self.firefox / 'profiles.ini').write_text(f'[Profile0]\nPath={elsewhere}\nIsRelative=0\n')
        paths = [path for _kind, path in history_databases(self.backend)]
        self.assertIn((elsewhere / 'places.sqlite').resolve(), paths)

    def test_reports_downloads_saved_anywhere_once_and_only_new_ones(self):
        start = time.time()
        saved = str(self.root / 'Some folder' / 'setup me.zip')
        chromium_profile(self.chrome, [('/old/before-start.zip', start - 60, 1),
                                       (saved, start + 1, 1), ('/still/downloading.zip', start + 2, 0)])
        firefox_profile(self.firefox, [(str(self.root / 'Documents' / 'report.pdf'), start + 3, 1),
                                       (str(self.root / 'cancelled.iso'), start + 4, 3)])
        history = DownloadHistory(self.backend, now=start)
        self.assertEqual(sorted(history.new_downloads()), sorted([saved, str(self.root / 'Documents' / 'report.pdf')]))
        self.assertEqual(history.new_downloads(), [])  # unchanged databases are not copied again

    def test_the_same_file_downloaded_again_is_reported_again(self):
        start = time.time()
        path = str(self.root / 'file.zip')
        database = chromium_profile(self.chrome, [(path, start + 1, 1)])
        history = DownloadHistory(self.backend, now=start)
        self.assertEqual(history.new_downloads(), [path])
        with closing(sqlite3.connect(database)) as db, db:
            db.execute('INSERT INTO downloads (target_path, end_time, state) VALUES (?, ?, 1)',
                       (path, int((start + 9) * 1_000_000) + CHROMIUM_EPOCH_OFFSET))
        os.utime(database, ns=(time.time_ns(), time.time_ns() + 1_000_000_000))
        self.assertEqual(history.new_downloads(), [path])

    def test_unreadable_or_huge_databases_are_skipped(self):
        profile = self.chrome / 'Default'
        profile.mkdir(parents=True)
        (profile / 'History').write_bytes(b'not a database')
        self.assertEqual(DownloadHistory(self.backend, now=0).new_downloads(), [])
        with patch('core.browser_downloads.MAX_DATABASE_BYTES', 1):
            database = chromium_profile(self.root / 'big', [('/x/y.zip', time.time() + 5, 1)])
            history = DownloadHistory(SimpleNamespace(browser_profile_locations=lambda: [
                ('Chrome', database.parent.parent, 'chromium')]), now=0)
            self.assertEqual(history.new_downloads(), [])


if __name__ == '__main__':
    unittest.main()
