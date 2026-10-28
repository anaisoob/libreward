"""Background folder monitoring, independent of the GUI.

`libreward --monitor` runs this agent from the platform's user service (a
systemd user unit on Linux, the Run key on Windows): it starts at login, keeps
running when the window is closed, follows the saved settings, scans new and
changed files, runs scheduled Quick scans, notifies the desktop and keeps
LibreWard's own virus database current. The GUI reads its state file; the agent never writes config.json.
"""
import json
import os
import signal
import sys
import threading
import time

from backends import backend
from config import CONFIG_FILE, load_config
from core.db_manager import (
    auto_update_due,
    last_update_attempt,
    own_database_needs_refresh,
    run_freshclam_update,
)
from core.dependencies import missing_components, missing_message
from core.policy import policy_signature
from core.runtime import check_startup, is_update_locked
from core.scan_service import ScanService, scan_outcome
from excludes import get_active_exclude_patterns

CONFIG_INTERVAL = 2
BROWSER_INTERVAL = 10
HISTORY_INTERVAL = 10
# A clamd started by the agent keeps the database loaded this long after a check.
CLAMD_IDLE = 10 * 60
STATUS_INTERVAL = 10 * 60
RETRY_INTERVAL = 60
DATABASE_INTERVAL = 10 * 60
NOTIFICATION_RETRY = 30
NOTIFICATION_GIVE_UP = 30 * 60
# Repeated failures of the same batch notify once instead of every minute.
FAILURES_BEFORE_NOTICE = 3
BATCH_SIZE = 64
MAX_THREATS = 100
# A check that takes longer than this says "Checking…" while it runs.
SLOW_CHECK = 2
# A download that disappeared without being checked (cancelled) loses its
# "Waiting" notification after this. Firefox moves a download to the folder chosen
# in its dialog; the browser's download list then finds it well within this time.
STALE_DOWNLOAD = 30
MAX_LOG_BYTES = 1024 * 1024
# Scheduled Quick scans: run when this long has passed since the last one started,
# so a scan missed while the computer was off runs soon after the next login.
SCHEDULES = {'daily': 24 * 60 * 60, 'weekly': 7 * 24 * 60 * 60}
# Not right at login, while the desktop and applications start.
SCHEDULE_DELAY = 10 * 60
SCHEDULE_RETRY = 60 * 60
# EX_CONFIG: a component is missing; restarting does not help.
MISSING_COMPONENT_EXIT = 78


def monitor_dir():
    return backend.data_dir() / 'monitor'


def lock_file():
    return monitor_dir() / 'agent.lock'


def state_file():
    return monitor_dir() / 'state.json'


def gui_lock_file():
    """Held by an open LibreWard window."""
    return monitor_dir() / 'gui.lock'


def chosen_folders(config):
    return [os.path.abspath(root) for root in config.get('watched_folders', []) if isinstance(root, str) and root]


def follows_browsers(config):
    """Also protect the folders browsers download to, including ones chosen later."""
    return config.get('follow_download_folders', True) is not False


def threats_only(config):
    """Notify only about dangerous files, not about downloads and clean results."""
    return config.get('notify_threats_only', False) is True


def monitoring_enabled(config):
    return bool(config.get('watch_folders_enabled', False)) and bool(chosen_folders(config) or follows_browsers(config))


def scheduled_interval(config):
    """Seconds between scheduled Quick scans, or None when they are off."""
    return SCHEDULES.get(config.get('scheduled_scan'))


def agent_needed(config):
    """The background agent runs for protection of new files or for scheduled scans."""
    return monitoring_enabled(config) or scheduled_interval(config) is not None


def scheduled_scan_due(now, last, interval):
    """`last`: when the last finished scheduled scan started (time.time())."""
    if interval is None:
        return False
    if not isinstance(last, (int, float)):
        return True
    return not 0 <= now - last < interval  # also when the clock was set back


def last_scheduled_scan(state):
    last = state.get('scheduled_scan')
    return last if isinstance(last, dict) else {}


def monitor_settings(config, discovered=()):
    """(roots, exclude patterns) to watch, or None when monitoring is off."""
    if not monitoring_enabled(config):
        return None
    roots = list(dict.fromkeys(chosen_folders(config) + (
        [os.path.abspath(path) for path in discovered] if follows_browsers(config) else [])))
    patterns = get_active_exclude_patterns(set(config.get('enabled_common_excludes', [])),
                                           config.get('user_excludes', []))
    # LibreWard's own runtime, database and config changes must not feed back
    # into monitoring when a user watches their home directory.
    patterns.extend(str(path) for path in (backend.data_dir(), backend.config_dir(), backend.log_dir()))
    return roots, patterns


def read_state():
    try:
        state = json.loads(state_file().read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}
    return state if isinstance(state, dict) else {}


def write_state(state):
    path = state_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f'{path.name}.{os.getpid()}.tmp')
    temporary.write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding='utf-8')
    os.replace(temporary, path)


def file_names(paths, limit=3):
    names = ', '.join(os.path.basename(path) for path in paths[:limit])
    return names + (f' (+{len(paths) - limit} more)' if len(paths) > limit else '')


def scan_notification(result, paths):
    """(title, message, warning) for a finished automatic scan."""
    threats = [path for path, _threat in result.get('infected', [])]
    if threats or result.get('infected_found'):
        return ('⚠ LibreWard — dangerous file found',
                (f'{scan_outcome(result)}\n{file_names(threats or paths)}\n'
                 'Do not open it. LibreWard asks what to do with it.'), True)
    return ('LibreWard — new files checked',
            f"{scan_outcome(result)}\nChecked: {result.get('scanned', 0)} file(s).\n{file_names(paths)}",
            bool(result.get('warnings')))


class _Discard:
    """Scan output sink: the agent keeps results, not the per-file log."""
    def put(self, _item):
        pass


class MonitorAgent:
    def __init__(self, *, notify=None, close_notification=None, open_application=None,
                 gui_running=None, log=None):
        self.notify = notify or backend.send_desktop_notification
        self.close_notification = close_notification or backend.close_desktop_notification
        self.open_application = open_application or backend.open_application
        self.gui_running = gui_running or backend.gui_running
        self.log = log or _log
        self.stopped = threading.Event()
        self.config = {}
        self.config_signature = None
        self.config_checked = float('-inf')
        self.settings = None
        self.discovered = []
        self.browser_signature = None
        self.browser_checked = float('-inf')
        self.history = None
        self.history_checked = float('-inf')
        self.clamd = None
        self.clamd_used = 0
        self.monitor = None
        self.monitor_retry_at = 0
        self.status = None
        self.status_checked = float('-inf')
        self.retry_at = 0
        self.failures = 0
        self.service = None
        self.scanning = []
        self.database_thread = None
        self.database_checked = time.monotonic() - DATABASE_INTERVAL + 60
        self.scheduled_thread = None
        self.scheduled_service = None
        self.scheduled_started = None
        self.scheduled_system_check = None
        self.schedule_not_before = time.monotonic() + SCHEDULE_DELAY
        self.undelivered = []
        # Downloads announced in a notification, which later shows their result:
        # partial file -> None while downloading, or when it disappeared.
        self.announced = {}
        self.notification_lock = threading.Lock()
        previous = read_state()
        self.state = {key: previous[key] for key in
                      ('threats', 'last_scan', 'pending', 'database_update_at', 'database_update_ok',
                       'scheduled_scan', 'scheduled_scan_error', 'system_check')
                      if key in previous}

    # ── lifecycle ───────────────────────────────────────────────────

    def run(self):
        lock = backend.acquire_instance_lock(lock_file())
        if lock is None:
            self.log('LibreWard folder monitoring is already running.')
            return 0
        try:
            self.reload_config()
            missing = missing_components(['watchdog']) if monitoring_enabled(self.config) else {}
            if missing:
                message = missing_message(missing, 'Folder monitoring')
                self.update_state(status='error', message=message)
                self.log(message)
                return MISSING_COMPONENT_EXIT
            self.update_state(running=True, pid=os.getpid(), started=time.time(),
                              status='starting', message='Starting folder monitoring…',
                              notifications=backend.notifications_available())
            self.log('LibreWard folder monitoring started.')
            return self._loop()
        finally:
            self._stop_monitor()
            self.release_clamd(force=True)
            self.stop_scheduled_scan()
            thread = self.database_thread
            if thread is not None:
                thread.join(timeout=5)
            self.update_state(running=False, pid=None, scheduled_scan_running=None)
            self.log('LibreWard folder monitoring stopped.')
            lock.close()

    def stop(self):
        self.stopped.set()
        for service in (self.service, self.scheduled_service):
            if service is not None:
                service.stop()

    def reload(self):
        """Read the settings again at the next check (SIGHUP)."""
        self.config_signature = None
        self.config_checked = float('-inf')

    def _loop(self):
        while not self.stopped.is_set():
            now = time.monotonic()
            if now - self.config_checked >= CONFIG_INTERVAL:
                self.config_checked = now
                self.reload_config()
                self.follow_browsers(now)
                if not agent_needed(self.config):
                    self.update_state(status='off', message='Folder monitoring is off.')
                    self.log('Folder monitoring and scheduled scans are turned off in the settings.')
                    return 0
                settings = monitor_settings(self.config, self.discovered)
                if settings is None:
                    if self.monitor is not None:
                        self._stop_monitor()
                        self.settings = None
                        self.log('Folder monitoring is turned off in the settings.')
                    self.update_state(status='off', message='Folder monitoring is off.')
                elif settings != self.settings or (self.monitor_failed() and now >= self.monitor_retry_at):
                    self.start_monitor(settings)
            self.check_status()
            self.maybe_update_database()
            self.run_schedule()
            self.follow_downloads(now)
            self.scan_ready()
            self.release_clamd()
            self.retry_notifications()
            self.stopped.wait(1)
        return 0

    def follow_browsers(self, now):
        """Pick up a download folder chosen in a browser after protection was turned on."""
        from core.download_folders import discover_download_folders, settings_signature
        if (not monitoring_enabled(self.config) or not follows_browsers(self.config)
                or now - self.browser_checked < BROWSER_INTERVAL):
            return
        self.browser_checked = now
        try:
            signature = settings_signature()
            if signature == self.browser_signature:
                return
            self.browser_signature = signature
            discovered = [folder.path for folder in discover_download_folders()]
        except OSError:
            return
        if discovered != self.discovered:
            added = set(discovered) - set(self.discovered)
            if self.discovered and added:
                self.log(f'Now also protecting {len(added)} download folder(s) chosen in a browser.')
            self.discovered = discovered
            self.update_state(discovered_folders=discovered)

    def follow_downloads(self, now):
        """Files saved anywhere with "Save as", from the browsers' lists of downloads."""
        from core.browser_downloads import DownloadHistory
        if (self.monitor is None or not follows_browsers(self.config)
                or now - self.history_checked < HISTORY_INTERVAL):
            return
        self.history_checked = now
        if self.history is None:
            self.history = DownloadHistory()  # downloads from before are not checked
            return
        for path in self.history.new_downloads():
            if os.path.isfile(path):
                # Already checked when it was in a watched folder: not checked twice.
                self.monitor.changed(path, finished=True, reason="in a browser's list of downloads")

    def release_clamd(self, force=False):
        if self.clamd is not None and (force or time.monotonic() - self.clamd_used > CLAMD_IDLE):
            try:
                self.clamd.close()
            except OSError as exc:
                self.log(f'Cannot stop the faster scanner: {exc}')
            self.clamd = None

    def reload_config(self):
        try:
            mtime = CONFIG_FILE.stat().st_mtime_ns
        except OSError:
            mtime = None
        # An administrator's policy changes the settings too.
        signature = (mtime, policy_signature())
        if signature == self.config_signature:
            return
        config = load_config()
        if config is None and mtime is not None:
            return  # unreadable right now: keep the previous settings and try again
        self.config_signature = signature
        self.config = config if isinstance(config, dict) else {}

    # ── watching ────────────────────────────────────────────────────

    def start_monitor(self, settings):
        from core.folder_watch import FolderMonitor
        # Files that changed before a restart or a settings change are still checked.
        carried = self._pending_paths() + [path for path in self.state.get('pending', []) if isinstance(path, str)]
        if self.monitor is not None:
            self.monitor.stop()
        self.settings = settings
        roots, patterns = settings
        self.monitor = FolderMonitor(roots, patterns)
        self.monitor.start()
        for path in dict.fromkeys(carried):
            if os.path.isfile(path):
                self.monitor.changed(path)
        self.monitor_retry_at = time.monotonic() + RETRY_INTERVAL
        self.update_state(folders=len(roots), pending=[])
        self.log(f'Watching {len(roots)} folder(s).')

    def monitor_failed(self):
        return self.monitor is not None and not self.monitor.thread.is_alive()

    def _pending_paths(self):
        monitor = self.monitor
        if monitor is None:
            return list(self.scanning)
        with monitor.lock:
            return list(dict.fromkeys([*self.scanning, *monitor.pending]))

    def _stop_monitor(self):
        pending = self._pending_paths()
        if self.monitor is not None:
            self.monitor.stop()
            self.monitor = None
        if pending:
            self.update_state(pending=pending)

    def check_status(self):
        interval = STATUS_INTERVAL if self.status is not None and self.status.can_scan else RETRY_INTERVAL
        if time.monotonic() - self.status_checked < interval:
            return
        self.status_checked = time.monotonic()
        # Installing libnotify later is noticed without restarting the agent.
        self.update_state(notifications=backend.notifications_available())
        try:
            self.status = check_startup()
        except Exception as exc:  # noqa: BLE001 - a broken runtime must not end monitoring
            self.status = None
            self.log(f'Cannot check the antivirus engine: {exc}')

    # ── scanning ────────────────────────────────────────────────────

    def scan_ready(self):
        monitor = self.monitor
        if monitor is None or self.stopped.is_set():
            return
        if self.monitor_failed():
            self.update_state(status='error', message=f'Monitoring needs attention: {monitor.error or "stopped"}. '
                                                      'LibreWard tries again in a minute.')
            return
        if self.status is None or not self.status.can_scan:
            self.update_state(status='needs-setup',
                              message='Monitoring is waiting for the antivirus engine and virus database.')
            return
        if is_update_locked():
            self.update_state(status='paused', message='Monitoring is paused while ClamAV is being updated.')
            return
        if monitor.error:
            self.update_state(status='error', message=f'Monitoring needs attention: {monitor.error}')
        elif not self.settings[0]:
            self.update_state(status='error', message='No folder to protect was found. Choose folders to protect.')
        else:
            self.update_state(status='watching',
                              message=f'Monitoring {len(self.settings[0])} folder(s), including subfolders.')
        downloads = monitor.downloads()
        self.update_state(downloading=['a download'] * min(len(downloads), 5))
        self.announce(downloads)
        self.forget_removed_threats()
        if time.monotonic() < self.retry_at:
            return
        paths = [path for path in monitor.ready(BATCH_SIZE) if os.path.isfile(path)]
        if paths:
            self.update_state(checking=file_names(paths))
            try:
                self.scan(paths)
            finally:
                self.update_state(checking=None)

    def forget_removed_threats(self):
        """Drop threats whose file is gone, so a new file with that name starts fresh."""
        threats = self.state.get('threats', [])
        present = [entry for entry in threats if isinstance(entry, dict)
                   and isinstance(entry.get('path'), str) and os.path.lexists(entry['path'])]
        if len(present) != len(threats):
            self.update_state(threats=present)

    def announce(self, downloads):
        """downloads: partial files from FolderMonitor.downloads()."""
        now = time.monotonic()
        current = set(downloads)
        for partial in downloads:
            if partial not in self.announced and not threats_only(self.config):
                self.send('LibreWard — download', 'Waiting for a download to finish. '
                          'LibreWard checks it for viruses right after.', False, replace=f'download:{partial}')
            self.announced[partial] = None
        for partial, gone in list(self.announced.items()):
            if partial not in current and gone is None:
                self.announced[partial] = now
            elif gone is not None and now - gone > STALE_DOWNLOAD:
                del self.announced[partial]
                self.close_notification(f'download:{partial}')

    def close_vanished_downloads(self):
        """Firefox renames its temporary partial file; that "Waiting" ends with the result."""
        for partial, gone in list(self.announced.items()):
            if gone is not None:
                del self.announced[partial]
                self.close_notification(f'download:{partial}')

    def scan(self, paths):
        _roots, patterns = self.settings
        self.scanning = paths
        partial = self.monitor.came_from(paths[0]) if len(paths) == 1 and self.monitor is not None else None
        if partial is not None and partial in self.announced:
            del self.announced[partial]
            key = f'download:{partial}'  # "Checking…" updates the download's "Waiting"
        else:
            key = f'check:{paths[0]}'
        done = threading.Event()

        def slow():
            # Large files take a while; say that the check is running.
            with self.notification_lock:
                if not done.is_set() and not threats_only(self.config):
                    self.send('LibreWard — checking', f'Checking {file_names(paths)} for viruses…',
                              False, replace=key)

        timer = threading.Timer(SLOW_CHECK, slow)
        timer.daemon = True
        timer.start()
        failed = True
        try:
            failed = self._scan(paths, patterns, key, done)
        finally:
            with self.notification_lock:
                done.set()
            timer.cancel()
            if failed:
                # No result to show: never leave "Checking…" behind (tried again later).
                self.close_notification(key)

    def _scan(self, paths, patterns, key, done):
        """Check files and report the result; True when the check did not finish.

        `done` is set together with sending the result, so a "Checking…" that is
        due at the same moment can never replace the result afterwards.
        """
        for path in paths[:5]:
            self.log(f'Checking {os.path.basename(path)} ({self.monitor.reason(path)}).')
        service = ScanService(_Discard(), scan_profile=self.config.get('scan_profile', 'standard'),
                              workers=self.config.get('scan_workers', 'auto'))
        self.service = service
        # clamscan loads the whole database for every check. With clamd installed, a
        # running system daemon is used, or the agent starts its own and keeps it for
        # CLAMD_IDLE after the last check, so a series of downloads is checked quickly.
        parallel = bool(self.config.get('parallel_scanning', True)
                        and (self.status.clamd_running or self.status.clamd_path))
        from core.scan_policy import scan_limits
        limits = scan_limits(self.config.get('scan_profile', 'standard'), self.config.get('scan_workers', 'auto'))
        if self.clamd is not None and (not parallel or self.clamd.limits != limits):
            self.release_clamd(force=True)  # settings changed since it started
        if parallel and self.clamd is None:
            from core.clamd import ClamdSession
            self.clamd = ClamdSession(backend, self.config.get('scan_profile', 'standard'),
                                      self.config.get('scan_workers', 'auto'))
        try:
            service.run(paths, patterns, self.status.runtime.clamscan, parallel=parallel,
                        session=self.clamd if parallel else None)
        finally:
            self.service = None
            self.clamd_used = time.monotonic()
        result = service.result or {'errors': True}
        if self.stopped.is_set():
            return True  # self.scanning is saved as pending for the next start
        self.scanning = []
        if result.get('errors') or result.get('stopped'):
            self.failures += 1
            self.retry_at = time.monotonic() + RETRY_INTERVAL
            self.status_checked = float('-inf')
            for path in paths:
                self.monitor.changed(path, retry=True)
            self.log(f'Automatic scan of {len(paths)} file(s) failed; trying again in a minute.')
            if self.failures == FAILURES_BEFORE_NOTICE:
                self.send('⚠ LibreWard — automatic scan failed',
                          f'New files could not be checked: {file_names(paths)}\n'
                          'LibreWard keeps trying. Open LibreWard to check the antivirus setup.', True)
            return True
        self.failures = 0
        found = time.time()
        self.update_state(threats=self.add_threats(result.get('infected', []), found), last_scan={
            'time': found, 'outcome': scan_outcome(result), 'files': len(paths),
            'names': file_names(paths)})
        self.log(f"Automatic scan of {len(paths)} file(s): {scan_outcome(result)}")
        title, message, warning = scan_notification(result, paths)
        dangerous = bool(result.get('infected') or result.get('infected_found'))
        with self.notification_lock:
            done.set()
            # The result is a new notification: GNOME does not reliably show a banner
            # for an update in place of a "Waiting" or "Checking…" it already showed.
            self.close_notification(key)
            self.close_vanished_downloads()
            if dangerous or not threats_only(self.config):
                self.send(title, message, warning)
        if result.get('infected') and not self.gui_running():
            # An open window asks what to do by itself; otherwise LibreWard opens to ask.
            self.show_threats()
        return False

    def add_threats(self, infected, found):
        """The listed threats with `infected` [(path, threat)] found again or for the first time."""
        threats = [entry for entry in self.state.get('threats', [])
                   if not any(entry.get('path') == path for path, _threat in infected)]
        threats += [{'path': path, 'threat': threat, 'time': found} for path, threat in infected]
        return threats[-MAX_THREATS:]

    def show_threats(self):
        self.log('Opening LibreWard to ask about a dangerous file.')
        try:
            self.open_application('--threats')
        except OSError as exc:
            self.log(f'Cannot open LibreWard: {exc}')

    # ── scheduled scans ─────────────────────────────────────────────

    def run_schedule(self):
        """Start a scheduled Quick scan when it is due; report one that has finished."""
        if self.scheduled_thread is not None:
            if not self.scheduled_thread.is_alive():
                self.finish_scheduled_scan()
            return
        interval = scheduled_interval(self.config)
        if (time.monotonic() < self.schedule_not_before or not scheduled_scan_due(
                time.time(), last_scheduled_scan(self.state).get('started'), interval)):
            self.update_state(scheduled_scan_waiting=None)
        elif self.status is None or not self.status.can_scan:
            self.update_state(scheduled_scan_waiting='Waiting for the antivirus engine and virus database.')
        elif is_update_locked():
            self.update_state(scheduled_scan_waiting='Waiting until ClamAV has been updated.')
        elif self.database_thread is not None and self.database_thread.is_alive():
            pass  # scan with the refreshed virus database
        else:
            self.start_scheduled_scan()

    def start_scheduled_scan(self):
        """The same Quick scan as the window's button, in a thread: new files are still checked meanwhile."""
        from core.quick_scan import quick_scan_excludes, quick_scan_targets
        roots = quick_scan_targets()
        patterns = get_active_exclude_patterns(set(self.config.get('enabled_common_excludes', [])),
                                               self.config.get('user_excludes', [])) + quick_scan_excludes()
        service = ScanService(_Discard(), scan_profile=self.config.get('scan_profile', 'standard'),
                              workers=self.config.get('scan_workers', 'auto'))
        # A running clamd checks files in parallel; otherwise one clamscan does it,
        # without starting a daemon for a scan that runs rarely.
        parallel = bool(self.config.get('parallel_scanning', True) and self.status.clamd_running)
        clamscan = self.status.runtime.clamscan

        def work():
            try:
                service.run(roots, patterns, clamscan, parallel=parallel)
            except Exception as exc:  # noqa: BLE001 - reported as a scan that did not finish
                self.log(f'Scheduled scan failed: {exc}')
                return
            if not service.stop_requested:
                # Signs of hidden programs, which virus signatures do not find.
                from core.system_check import run_system_check
                try:
                    self.scheduled_system_check = run_system_check()
                except Exception as exc:  # noqa: BLE001 - the virus scan result still counts
                    self.log(f'System check failed: {exc}')

        self.scheduled_service = service
        self.scheduled_system_check = None
        self.scheduled_started = time.time()
        self.update_state(scheduled_scan_running=self.scheduled_started, scheduled_scan_waiting=None)
        self.log(f'Scheduled Quick scan of {len(roots)} folder(s) and file(s) started.')
        self.scheduled_thread = threading.Thread(target=work, name='scheduled-scan', daemon=True)
        self.scheduled_thread.start()

    def finish_scheduled_scan(self):
        service, started = self.scheduled_service, self.scheduled_started
        self.scheduled_thread = self.scheduled_service = self.scheduled_started = None
        self.update_state(scheduled_scan_running=None)
        if self.stopped.is_set():
            return  # it runs again after the next start
        result = service.result or {'errors': True}
        outcome = scan_outcome(result)
        if result.get('errors') or result.get('stopped'):
            self.schedule_not_before = time.monotonic() + SCHEDULE_RETRY
            self.update_state(scheduled_scan_error=time.time())
            self.log(f'Scheduled Quick scan did not finish ({outcome}); trying again in an hour.')
            return
        found = time.time()
        infected = result.get('infected', [])
        self.update_state(threats=self.add_threats(infected, found), scheduled_scan_error=None, scheduled_scan={
            'started': started, 'time': found, 'outcome': outcome, 'files': result.get('scanned', 0)})
        self.log(f"Scheduled Quick scan of {result.get('scanned', 0)} file(s): {outcome}")
        if infected or result.get('infected_found'):
            self.send(*scan_notification(result, []))
            if infected and not self.gui_running():
                self.show_threats()
        elif not threats_only(self.config):
            self.send('LibreWard — scheduled scan', f"{outcome}\nChecked: {result.get('scanned', 0)} file(s).",
                      bool(result.get('warnings')))
        self.report_system_check(self.scheduled_system_check)

    def report_system_check(self, check):
        if check is None:
            return
        from core.system_check import notification
        findings = check['findings']
        self.update_state(system_check={'time': check['time'], 'titles': [entry['title'] for entry in findings]})
        self.log(f'System check: {len(findings)} suspicious finding(s).')
        for entry in findings:
            self.log(f"Suspicious: {entry['title']}: {entry['detail']}")
        if findings:
            self.send(*notification(check), True)

    def stop_scheduled_scan(self):
        if self.scheduled_service is not None:
            self.scheduled_service.stop()
        if self.scheduled_thread is not None:
            self.scheduled_thread.join(timeout=10)

    # ── notifications ───────────────────────────────────────────────

    def send(self, title, message, warning, replace=None):
        delivered = self.notify(title, message, warning=warning, replace=replace)
        if not delivered and warning:
            # Threats and failures must reach the user, for example when the
            # desktop's notification service starts later than this agent.
            now = time.monotonic()
            self.undelivered.append((now, now + NOTIFICATION_RETRY, title, message))

    def retry_notifications(self):
        now = time.monotonic()
        waiting, self.undelivered = self.undelivered, []
        for queued, next_try, title, message in waiting:
            if now - queued > NOTIFICATION_GIVE_UP:
                continue
            if now < next_try:
                self.undelivered.append((queued, next_try, title, message))
            elif not self.notify(title, message, warning=True):
                self.undelivered.append((queued, now + NOTIFICATION_RETRY, title, message))

    # ── virus database ──────────────────────────────────────────────

    def maybe_update_database(self):
        """Keep LibreWard's own database current, like the GUI does while it is open."""
        status = self.status
        if (time.monotonic() - self.database_checked < DATABASE_INTERVAL
                or (self.database_thread is not None and self.database_thread.is_alive())
                or status is None or not status.can_update_db
                or not self.config.get('auto_update_database', True)):
            return
        self.database_checked = time.monotonic()
        last, succeeded = last_update_attempt(self.config, self.state)
        if not auto_update_due(time.time(), last, succeeded) or not own_database_needs_refresh():
            return
        freshclam = status.runtime.freshclam

        def work():
            try:
                result = run_freshclam_update(freshclam, wait=False)
                success, pending = bool(result[0]), getattr(result, 'pending', False)
            except Exception:  # noqa: BLE001 - retried later, like the GUI's refresh
                success, pending = False, False
            if pending:
                return  # another update is running; try again at the next check
            self.update_state(database_update_at=time.time(), database_update_ok=success)
            self.status_checked = float('-inf')
            self.log('Virus database updated automatically.' if success else
                     'Automatic virus database update did not finish; trying again later.')

        self.database_thread = threading.Thread(target=work, name='database-update', daemon=True)
        self.database_thread.start()

    # ── state for the GUI ───────────────────────────────────────────

    def update_state(self, **changes):
        if all(self.state.get(key) == value for key, value in changes.items()):
            return
        self.state.update(changes)
        try:
            write_state(dict(self.state, updated=time.time()))
        except OSError as exc:
            self.log(f'Cannot save the monitoring state: {exc}')


def _log(text):
    # Under systemd stderr goes to the journal; pythonw.exe has no stderr.
    if sys.stderr is not None:
        print(text, file=sys.stderr, flush=True)
        return
    try:
        path = backend.log_dir() / 'monitor.log'
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size > MAX_LOG_BYTES:
            path.replace(path.with_suffix('.log.old'))
        with path.open('a', encoding='utf-8') as stream:
            stream.write(time.strftime('%Y-%m-%d %H:%M:%S ') + text + '\n')
    except OSError:
        pass


def main():
    agent = MonitorAgent()
    signal.signal(signal.SIGTERM, lambda _signal, _frame: agent.stop())
    signal.signal(signal.SIGINT, lambda _signal, _frame: agent.stop())
    if hasattr(signal, 'SIGHUP'):
        signal.signal(signal.SIGHUP, lambda _signal, _frame: agent.reload())
    return agent.run()
