"""Native notifications plus periodic reconciliation, independent of the GUI."""
import os
import threading
import time

from backends import backend
from scanner import iter_scan_files, normalize_scan_roots
from excludes import path_is_excluded


DOWNLOAD_SUFFIXES = ('.crdownload', '.part', '.download', '.aria2', '.!qb', '.!ut', '.filepart')
# Files up to this size remember a digest, so a new modification time alone (as
# set by browsers from the server's Last-Modified) does not check them again.
DIGEST_LIMIT = 256 * 1024 * 1024


def incomplete_download(path):
    return str(path).lower().endswith(DOWNLOAD_SUFFIXES)


class FolderMonitor:
    def __init__(self, roots, excludes, *, settle=3):
        self.roots = normalize_scan_roots(roots)
        self.excludes = list(excludes)
        self.settle = settle
        self.pending = {}
        # Unfinished browser downloads: partial file -> when it was last seen.
        self.downloading = {}
        # Why a file is checked, for the agent's log.
        self.reasons = {}
        self.snapshot = {}
        self.dispatched = {}
        self.baseline_ready = threading.Event()
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.observer = None
        self.thread = None
        self.error = None

    def start(self):
        from watchdog.events import FileSystemEventHandler
        monitor = self

        class Handler(FileSystemEventHandler):
            def on_any_event(self, event):
                # Reads performed by ClamAV must not trigger another scan.
                if event.event_type == 'deleted' and not event.is_directory:
                    monitor.forget(event.src_path)
                    # Removing a sidecar may be the only completion event for
                    # an existing final file (Firefox / aria2).
                    if incomplete_download(event.src_path):
                        suffix = next(s for s in DOWNLOAD_SUFFIXES if event.src_path.lower().endswith(s))
                        final = event.src_path[:-len(suffix)]
                        monitor.finished(event.src_path)
                        monitor.changed(final, finished=True)
                    return
                if event.event_type not in ('created', 'modified', 'moved'):
                    return
                if event.is_directory:
                    monitor.reconcile.set()
                    return
                destination = getattr(event, 'dest_path', '') or event.src_path
                if event.event_type == 'moved':
                    monitor.forget(event.src_path)  # e.g. moved to quarantine
                renamed_partial = event.event_type == 'moved' and incomplete_download(event.src_path)
                if incomplete_download(destination):
                    # Chrome renames "Unconfirmed 123.crdownload" to "name.crdownload".
                    if renamed_partial:
                        monitor.finished(event.src_path)
                    monitor.started(destination)
                elif renamed_partial:
                    # The browser renamed its partial file: the download is complete.
                    monitor.finished(event.src_path)
                    monitor.changed(destination, finished=True)
                else:
                    monitor.changed(destination)

        self.reconcile = threading.Event()
        self.thread = threading.Thread(target=self._observe, args=(Handler(),), name='folder-monitor', daemon=True)
        self.thread.start()

    def _observe(self, handler):
        try:
            self.observer = backend.folder_observer()
            for root in self.roots:
                if self.stopped.is_set():
                    return
                self.observer.schedule(handler, root, recursive=True)
            if self.stopped.is_set():
                return
            self.observer.start()
            self._run()
        except Exception as exc:
            self.error = str(exc)
        finally:
            if self.observer:
                self.observer.stop()
                if self.observer.is_alive():
                    self.observer.join()

    def changed(self, path, *, retry=False, finished=False, reason=None):
        """Queue a new or changed file; a finished download needs no settling time."""
        path = os.path.abspath(path)
        if not incomplete_download(path) and not path_is_excluded(path, self.excludes):
            with self.lock:
                reason = reason or ('checking again' if retry else 'download finished' if finished
                                    else 'new or changed file')
                if retry:
                    self.dispatched.pop(path, None)
                try:
                    signature = self._signature(os.stat(path))
                except OSError:
                    signature = None
                waiting = self.pending.get(path)
                if finished:
                    self.pending[path] = (time.monotonic() - self.settle, signature)
                    self.reasons[path] = reason
                elif waiting is None or waiting[1] is None or waiting[1] != signature:
                    self.pending[path] = (time.monotonic(), None)
                    self.reasons[path] = reason
                # Otherwise unchanged since it was queued, e.g. the folder check after a
                # finished download: keep its place (and reason) instead of waiting again.

    def forget(self, path):
        """A file was deleted or moved away: a new file at this path is checked again."""
        with self.lock:
            self.dispatched.pop(os.path.abspath(path), None)

    def started(self, partial):
        partial = os.path.abspath(partial)
        if not path_is_excluded(partial, self.excludes):
            with self.lock:
                self.downloading[partial] = time.monotonic()

    def finished(self, partial):
        partial = os.path.abspath(partial)
        with self.lock:
            self.downloading.pop(partial, None)

    def reason(self, path):
        with self.lock:
            return self.reasons.pop(os.path.abspath(path), 'new or changed file')

    def downloads(self):
        """Partial files of downloads in progress, oldest first.

        Their names are not shown: browsers use temporary, sometimes random, names
        until the download is finished; the check then shows the real one.
        """
        with self.lock:
            for partial in [path for path in self.downloading if not os.path.exists(path)]:
                del self.downloading[partial]
            return sorted(self.downloading, key=self.downloading.get)


    def _run(self):
        # Establish a baseline; watching is separate from a full folder scan.
        while not self.stopped.is_set():
            try:
                current = {}
                for path in iter_scan_files(self.roots, self.excludes, self.stopped.is_set):
                    try:
                        stat = os.stat(path)
                    except OSError:
                        continue
                    signature = self._signature(stat)
                    current[path] = signature
                    if self.baseline_ready.is_set() and self.snapshot.get(path) != signature:
                        self.changed(path, reason='found by the folder check')
                with self.lock:
                    for path in self.snapshot.keys() - current.keys():
                        self.dispatched.pop(path, None)
                self.snapshot = current
                self.baseline_ready.set()
                missing = [root for root in self.roots if not os.path.isdir(root)]
                self.error = 'Watched folder unavailable: ' + ', '.join(missing) if missing else None
            except Exception as exc:
                self.error = str(exc)
            self.reconcile.wait(60)
            self.reconcile.clear()

    @staticmethod
    def _signature(stat):
        # Contents only: browsers add metadata (such as the download address) after
        # saving, which changes ctime but must not check the file a second time.
        return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)

    def ready(self, limit=64):
        ready = []
        now = time.monotonic()
        with self.lock:
            for path, (changed, signature) in list(self.pending.items()):
                if now - changed < self.settle:
                    continue
                if any(os.path.exists(path + suffix) for suffix in ('.aria2', '.part', '.crdownload', '.!qB', '.!ut')):
                    self.pending[path] = (now, None)
                    continue
                try:
                    stat = os.stat(path)
                    if not os.path.isfile(path):
                        del self.pending[path]
                        continue
                except OSError:
                    del self.pending[path]
                    self.dispatched.pop(path, None)
                    continue
                current = self._signature(stat)
                checked = self.dispatched.get(path)
                if checked is not None and checked[0] == current:
                    del self.pending[path]
                    continue
                if signature != current:
                    self.pending[path] = (now, current)
                    continue
                digest = file_digest(path, stat.st_size)
                same_file = checked is not None and checked[0][:2] == current[:2]  # device and inode
                if same_file and digest is not None and checked[1] == digest:
                    # The same file with a new modification time only: checked already.
                    # A new file with the same contents (downloaded again) is checked.
                    self.dispatched[path] = (current, digest)
                    del self.pending[path]
                    continue
                ready.append(path)
                self.dispatched[path] = (current, digest)
                del self.pending[path]
                if len(ready) == limit:
                    break
        return ready

    def stop(self):
        self.stopped.set()
        if hasattr(self, 'reconcile'):
            self.reconcile.set()
        if self.observer:
            self.observer.stop()
        if self.thread:
            self.thread.join(timeout=.1)



def file_digest(path, size):
    """SHA-256 of a file up to DIGEST_LIMIT, or None."""
    import hashlib
    if size > DIGEST_LIMIT:
        return None
    digest = hashlib.sha256()
    try:
        with open(path, 'rb') as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()
