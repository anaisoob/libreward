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
                        monitor.changed(event.src_path[:-len(suffix)])
                    return
                if event.event_type not in ('created', 'modified', 'moved'):
                    return
                if not event.is_directory:
                    monitor.changed(getattr(event, 'dest_path', '') or event.src_path)
                else:
                    monitor.reconcile.set()

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

    def changed(self, path, *, retry=False):
        path = os.path.abspath(path)
        if not incomplete_download(path) and not path_is_excluded(path, self.excludes):
            with self.lock:
                if retry:
                    self.dispatched.pop(path, None)
                self.pending[path] = (time.monotonic(), None)

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
