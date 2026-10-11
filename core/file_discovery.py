"""Bounded file discovery concurrent with scan requests."""
import queue
import threading
import time

from scanner import iter_scan_files


class FileDiscovery:
    def __init__(self, roots, excludes, stopped, report, processed, *, count_only=False):
        self.roots, self.excludes = roots, excludes
        self.count_only = count_only
        self.stopped, self.report, self.processed = stopped, report, processed
        self.queue = queue.Queue(maxsize=256)
        self.cancel = threading.Event()
        self.done = threading.Event()
        self.total = 0
        self.error = None
        self.started = time.monotonic()
        self.last_report = 0
        self.thread = threading.Thread(target=self._discover, name='file-discovery')

    def is_stopped(self):
        return self.cancel.is_set() or self.stopped()

    def notify(self, force=False):
        now = time.monotonic()
        if force or now - self.last_report >= .25:
            self.last_report = now
            self.report(('__DISCOVERY__', self.total, self.processed(),
                         self.done.is_set(), now - self.started))

    def _discover(self):
        try:
            for path in iter_scan_files(self.roots, self.excludes, self.is_stopped):
                if self.count_only:
                    self.total += 1
                    self.notify()
                    continue
                while not self.is_stopped():
                    try:
                        self.queue.put(path, timeout=.1)
                        self.total += 1
                        break
                    except queue.Full:
                        pass
                    self.notify()
                self.notify()
                if self.is_stopped():
                    break
        except Exception as exc:
            self.error = exc
        finally:
            self.done.set()
            self.notify(force=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.cancel.set()
        self.thread.join()

    def finish(self):
        self.thread.join()
        if self.error:
            raise self.error

    def __iter__(self):
        return self

    def __next__(self):
        while not self.is_stopped():
            try:
                return self.queue.get(timeout=.1)
            except queue.Empty:
                if self.done.is_set():
                    if self.error:
                        raise self.error
                    break
                self.notify()
        raise StopIteration

    def __len__(self):
        return self.total
