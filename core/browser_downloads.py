"""Finished browser downloads, wherever the user saved them.

Browsers keep a list of downloads with the full path of each file. Reading it
finds files saved with "Save as" or "Always ask where to save" outside the
watched folders. Only the downloads table is read, never visited websites, and
nothing leaves the computer. Browsers lock their databases while running, so a
private copy is read, and only after the database changed.
"""
import json
import os
import shutil
import sqlite3
import tempfile
import time
from contextlib import closing
from pathlib import Path
from urllib.parse import unquote, urlparse

from backends import backend

# Copying a much larger history database on every change would cost too much.
MAX_DATABASE_BYTES = 512 * 1024 * 1024
# Chromium counts microseconds from 1601-01-01.
CHROMIUM_EPOCH_OFFSET = 11_644_473_600 * 1_000_000
FIREFOX_FINISHED = 1


def history_databases(platform_backend=None):
    """(kind, path) of every browser profile's history database."""
    platform_backend = platform_backend or backend
    found = []
    for _label, root, kind in platform_backend.browser_profile_locations():
        root = Path(root)
        name = 'places.sqlite' if kind == 'firefox' else 'History'
        parents = [root, root / 'Profiles'] if kind == 'firefox' else [root]
        for parent in parents:
            try:
                profiles = [child for child in parent.iterdir() if child.is_dir()]
            except OSError:
                continue
            found += [(kind, profile / name) for profile in profiles if (profile / name).is_file()]
    return found


def _copy(path, directory):
    """Copy a database with its write-ahead log, so recent downloads are included."""
    if path.stat().st_size > MAX_DATABASE_BYTES:
        raise OSError('History database too large to copy.')
    copy = Path(directory) / 'history.sqlite3'
    shutil.copyfile(path, copy)
    for suffix in ('-wal', '-journal'):
        source = Path(str(path) + suffix)
        if source.is_file():
            shutil.copyfile(source, Path(str(copy) + suffix))
    return copy


def chromium_downloads(database, since):
    """(path, finish time) of downloads finished after `since` (Unix seconds)."""
    after = int(since * 1_000_000) + CHROMIUM_EPOCH_OFFSET
    with closing(sqlite3.connect(database)) as connection:
        rows = connection.execute('SELECT target_path, end_time FROM downloads WHERE state = 1 AND end_time > ?',
                                  (after,)).fetchall()
    return [(path, finished) for path, finished in rows if isinstance(path, str) and path]


def firefox_downloads(database, since):
    """Firefox stores downloads as page annotations: the target file and its state."""
    after = int(since * 1_000_000)  # PRTime: microseconds
    with closing(sqlite3.connect(database)) as connection:
        rows = connection.execute(
            "SELECT target.content, meta.content, meta.lastModified FROM moz_annos AS meta "
            "JOIN moz_anno_attributes AS meta_name ON meta.anno_attribute_id = meta_name.id "
            "JOIN moz_annos AS target ON target.place_id = meta.place_id "
            "JOIN moz_anno_attributes AS target_name ON target.anno_attribute_id = target_name.id "
            "WHERE meta_name.name = 'downloads/metaData' AND target_name.name = 'downloads/destinationFileURI' "
            "AND meta.lastModified > ?", (after,)).fetchall()
    paths = []
    for uri, metadata, modified in rows:
        try:
            if json.loads(metadata).get('state') != FIREFOX_FINISHED:
                continue
        except (TypeError, ValueError, AttributeError):
            continue
        parsed = urlparse(uri or '')
        if parsed.scheme == 'file' and parsed.path:
            paths.append((unquote(parsed.path), modified))
    return paths


class DownloadHistory:
    """Report each download finished after this object was created, once."""

    def __init__(self, platform_backend=None, now=None):
        self.backend = platform_backend or backend
        self.since = time.time() if now is None else now
        self.signatures = {}
        self.reported = set()

    def new_downloads(self):
        paths = []
        for kind, database in history_databases(self.backend):
            signature = []
            for path in (database, Path(str(database) + '-wal')):
                try:
                    signature.append(path.stat().st_mtime_ns)
                except OSError:
                    signature.append(None)
            if self.signatures.get(database) == signature:
                continue
            self.signatures[database] = signature
            try:
                with tempfile.TemporaryDirectory(prefix='libreward-history-') as directory:
                    copy = _copy(database, directory)
                    found = (firefox_downloads if kind == 'firefox' else chromium_downloads)(copy, self.since)
            except (OSError, sqlite3.Error):
                continue  # locked mid-write or a different schema; tried again after the next change
            for path, finished in found:
                # The same file downloaded again later is reported again.
                if (path, finished) not in self.reported and os.path.isabs(path):
                    self.reported.add((path, finished))
                    paths.append(path)
        return paths
