"""Native notifications plus periodic reconciliation, independent of the GUI."""
import os
import threading
import time

from backends import backend
from scanner import iter_scan_files, normalize_scan_roots
from excludes import path_is_excluded


DOWNLOAD_SUFFIXES = ('.crdownload', '.part', '.download', '.aria2', '.!qb', '.!ut', '.filepart')


def incomplete_download(path):
    return str(path).lower().endswith(DOWNLOAD_SUFFIXES)


class FolderMonitor:
    def __init__(self, roots, excludes, *, settle=3):
        self.roots = normalize_scan_roots(roots)
        self.excludes = list(excludes)
        self.settle = settle
        self.pending = {}
        # Unfinished browser downloads (partial file -> when it was last seen).
        self.downloading = {}
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
                    # Removing a sidecar may be the only completion event for
                    # an existing final file (Firefox / aria2).
                    if incomplete_download(event.src_path):
                        suffix = next(s for s in DOWNLOAD_SUFFIXES if event.src_path.lower().endswith(s))
                        monitor.finished(event.src_path)
                        monitor.changed(event.src_path[:-len(suffix)], finished=True)
                    return
                if event.event_type not in ('created', 'modified', 'moved'):
                    return
                if event.is_directory:
                    monitor.reconcile.set()
                    return
                destination = getattr(event, 'dest_path', '') or event.src_path
                if event.event_type == 'moved' and incomplete_download(event.src_path):
                    # The browser renamed its partial file: the download is complete.
                    monitor.finished(event.src_path)
                    monitor.changed(destination, finished=True)
                elif incomplete_download(destination):
                    monitor.started(destination)
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

    def changed(self, path, *, retry=False, finished=False):
        """Queue a new or changed file; a finished download needs no settling time."""
        path = os.path.abspath(path)
        if not incomplete_download(path) and not path_is_excluded(path, self.excludes):
            with self.lock:
                if retry:
                    self.dispatched.pop(path, None)
                try:
                    signature = self._signature(os.stat(path))
                except OSError:
                    signature = None
                waiting = self.pending.get(path)
                if finished:
                    self.pending[path] = (time.monotonic() - self.settle, signature)
                elif waiting is None or waiting[1] is None or waiting[1] != signature:
                    self.pending[path] = (time.monotonic(), None)
                # Otherwise unchanged since it was queued, e.g. the folder check after a
                # finished download: keep its place instead of waiting again.

    def started(self, partial):
        partial = os.path.abspath(partial)
        if not path_is_excluded(partial, self.excludes):
            with self.lock:
                self.downloading[partial] = time.monotonic()

    def finished(self, partial):
        with self.lock:
            self.downloading.pop(os.path.abspath(partial), None)

    def downloads(self):
        """Names of downloads still in progress, for the status shown to the user."""
        with self.lock:
            for partial in [path for path in self.downloading if not os.path.exists(path)]:
                del self.downloading[partial]
            partials = sorted(self.downloading, key=self.downloading.get)
        names = []
        for partial in partials:
            suffix = next(s for s in DOWNLOAD_SUFFIXES if partial.lower().endswith(s))
            name = os.path.basename(partial[:-len(suffix)])
            # Chrome names a download "Unconfirmed 12345" until it is saved.
            names.append('a download' if name.startswith('Unconfirmed ') else name)
        return names

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
                        self.changed(path)
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
        return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)

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
                if self.dispatched.get(path) == current:
                    del self.pending[path]
                    continue
                if signature != current:
                    self.pending[path] = (now, current)
                    continue
                ready.append(path)
                self.dispatched[path] = current
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
