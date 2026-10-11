"""GUI-independent ClamAV scan worker shared by Tk and Qt frontends.

Run in a worker thread. Consumers poll output_queue on their UI thread.
"""
import queue
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

from core.clamd import ClamdSession, ScanCancelled, FileScanWarning, scan_file
from core.file_discovery import FileDiscovery
from core.scan_policy import scan_limits
from core.scan_warnings import WarningSummary, alert_warning, clean_reason
from excludes import mandatory_exclude_patterns

from backends import backend
from scanner import (build_clamscan_command,
                     parse_clamscan_result_line, should_log_line,
                     parse_clamscan_summary_value, _first_database_dir)


class ScanService:
    def __init__(self, output_queue=None, *, scan_profile='standard'):
        self.output_queue = output_queue if output_queue is not None else queue.Queue()
        self._stop = threading.Event()
        self.process = None
        self.scanned_files = 0
        self.summary_started = False
        self.result = None
        self.scan_profile = scan_profile
        self.warning_summary = WarningSummary()

    @property
    def stop_requested(self):
        return self._stop.is_set()

    def stop(self):
        self._stop.set()
        process = self.process
        if process is not None and process.poll() is None:
            try:
                backend.stop_process(process)
            except ProcessLookupError:
                pass  # process exited between poll and termination

    def run(self, scan_root, exclude_patterns, clamscan_path, *, parallel=False):
        infected_found = False
        errors_found = False
        warnings_found = False
        file_warning_found = False
        fatal_output_found = False
        infected = []
        total = 0
        scan_summary_lines: list[str] = []
        clamav_scanned_files = None
        clamav_alert_count = None
        non_threat_alerts = 0
        admin_hint = backend.scan_may_need_admin(scan_root)
        daemon = None
        used_parallel = False
        discovery = None

        try:
            exclude_patterns = list(dict.fromkeys([*exclude_patterns, *mandatory_exclude_patterns()]))
            if parallel:
                daemon = ClamdSession(backend, self.scan_profile)
                self.output_queue.put(("__STATUS__", "Preparing parallel scanner…"))
                try:
                    endpoint = daemon.acquire(clamscan_path, _first_database_dir(),
                                              lambda: self.stop_requested)
                except ScanCancelled:
                    return
                except OSError as exc:
                    daemon.close()
                    daemon = None
                    self.output_queue.put(f"Parallel scanner unavailable: {exc}. Using clamscan.\n")
                else:
                    used_parallel = True
                    source = 'existing' if daemon.reused else 'LibreWard-managed'
                    self.output_queue.put(f"Parallel scan: {source} clamd, up to {scan_limits(self.scan_profile).workers} files at once.\n")
                    if daemon.reused and self.scan_profile == 'extended':
                        self.output_queue.put('Existing clamd retains its configured scan limits. Use standard scanning to apply LibreWard large-file limits.\n')
                    self.output_queue.put(("__STATUS__", "scanning in parallel"))
                    self.output_queue.put(("__ACTIVITY__", "Activity: parallel scanning…"))
                    started = time.monotonic()
                    self.output_queue.put('Counting independently while scanning (scan queue limited to 256 files)...\n')
                    discovery = FileDiscovery(scan_root, exclude_patterns,
                                              lambda: self.stop_requested,
                                              lambda event: None, lambda: self.scanned_files)
                    counter = FileDiscovery(scan_root, exclude_patterns,
                                            lambda: self.stop_requested,
                                            self.output_queue.put, lambda: self.scanned_files,
                                            count_only=True)
                    self.progress_counter = counter
                    try:
                        with counter, discovery:
                            infected, warnings_found, errors_found = self._run_parallel(
                                discovery, endpoint, direct=not daemon.reused)
                            counter.finish()
                    finally:
                        self.progress_counter = None
                    total = discovery.total
                    self.output_queue.put(('__SET_TOTAL__', total))
                    infected_found = bool(infected)
                    clamav_scanned_files = self.scanned_files
                    if not self.stop_requested:
                        self.output_queue.put(("__PROGRESS__", total, total, True))
                    scan_summary_lines = [
                        '----------- SCAN SUMMARY -----------\n',
                        f'Processed files: {self.scanned_files} / {total}\n',
                        f'Infected files: {len(infected)}\n',
                        f'Warnings: {self.parallel_warnings}\n',
                        f'Errors: {self.parallel_errors}\n',
                        f'Time: {time.monotonic() - started:.3f} sec (excluding preparation)\n',
                    ]
                    for line in scan_summary_lines:
                        self.output_queue.put(line)
                    return

            self.output_queue.put('Counting files alongside standard scanning...\n')
            discovery = FileDiscovery(scan_root, exclude_patterns,
                                      lambda: self.stop_requested,
                                      self.output_queue.put, lambda: self.scanned_files,
                                      count_only=True)
            discovery.__enter__()
            known_files = set()
            if self.stop_requested:
                return

            cmd = build_clamscan_command(
                scan_root, exclude_patterns, clamscan_path=clamscan_path,
                scan_profile=self.scan_profile,
            )

            self.output_queue.put(
                "Command: clamscan with selected scan roots and active excludes\n\n"
            )

            self.output_queue.put(("__STATUS__", "scanning"))
            self.output_queue.put(("__ACTIVITY__", "Activity: clamscan is running..."))

            self.process = backend.start_process(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )

            # A stop request can arrive while Popen is starting.
            if self.stop_requested:
                backend.stop_process(self.process)

            if self.process.stdout:
                for line in self.process.stdout:
                    if self.stop_requested:
                        break

                    file_path, status = parse_clamscan_result_line(
                        line, known_files
                    )

                    if file_path:
                        self.scanned_files += 1

                        self.output_queue.put(("__CURRENT_FILE__", file_path))
                        if discovery.done.is_set():
                            self.output_queue.put(("__PROGRESS__", self.scanned_files, discovery.total, False))
                        else:
                            discovery.notify()

                        category = alert_warning(status)
                        if category:
                            non_threat_alerts += 1
                            warnings_found = True
                            self.warning_summary.add(file_path, status, category)
                            self.output_queue.put(f'{file_path}: {clean_reason(status)} WARNING\n')
                        elif "FOUND" in status:
                            infected_found = True
                            infected.append((file_path, status))
                            self.output_queue.put(line)

                        elif "ERROR" in status:
                            warnings_found = True
                            file_warning_found = True
                            self.warning_summary.add(file_path, status)
                            self.output_queue.put(f'{file_path}: {clean_reason(status)} WARNING\n')

                        continue

                    should_log, self.summary_started = should_log_line(
                        line, self.summary_started
                    )
                    if should_log:
                        if "WARNING" in line or "ERROR" in line:
                            warnings_found = True
                            access_problem = any(message in line.lower() for message in (
                                "can't open file", "permission denied", "can't get file status", "access denied",
                            ))
                            if access_problem:
                                file_warning_found = True
                                self.warning_summary.add('', line)
                            elif "ERROR" in line:
                                fatal_output_found = True
                            elif 'WARNING' in line:
                                self.warning_summary.add('', line)
                        self.output_queue.put(line)
                        if self.summary_started:
                            scan_summary_lines.append(line)
                            summary_scanned = parse_clamscan_summary_value(
                                line, "Scanned files"
                            )
                            if summary_scanned is not None:
                                clamav_scanned_files = summary_scanned
                            summary_alerts = parse_clamscan_summary_value(line, 'Infected files')
                            if summary_alerts is not None:
                                clamav_alert_count = summary_alerts

            if self.process is not None:
                return_code = self.process.wait()
            else:
                return_code = 2

            discovery.finish()
            total = discovery.total
            self.output_queue.put(('__SET_TOTAL__', total))

            if not self.stop_requested and return_code in (0, 1):
                self.output_queue.put(("__PROGRESS__", total, total, True))

            if return_code == 1:
                if infected or not non_threat_alerts or clamav_alert_count is None or clamav_alert_count > non_threat_alerts:
                    infected_found = True
            elif return_code != 0 and not self.stop_requested:
                # Per-file access failures with a scan summary remain warnings.
                if return_code == 2 and file_warning_found and self.summary_started and not fatal_output_found:
                    warnings_found = True
                else:
                    errors_found = True

            self.output_queue.put("\n========================================\n")
            self.output_queue.put("GUI RESULT\n")
            self.output_queue.put("========================================\n")

            if self.stop_requested:
                self.output_queue.put("Result: scan stopped by user.\n")
            elif infected_found:
                self.output_queue.put("Result: infected files found!\n")
            elif errors_found:
                self.output_queue.put("Result: scan failed.\n")
            elif warnings_found:
                self.output_queue.put("Result: scan completed with warnings.\n")
                self.output_queue.put(
                    "Some files could not be opened because they were locked, "
                    "changed during scanning, or access was denied.\n"
                )
            else:
                self.output_queue.put("Result: no infected files found.\n")

        except FileNotFoundError:
            errors_found = True
            self.output_queue.put(
                "ERROR: clamscan not found. Please install ClamAV first.\n"
            )
        except Exception as e:
            errors_found = True
            self.output_queue.put(f"ERROR: {e}\n")
        finally:
            if discovery is not None:
                discovery.__exit__()
                total = discovery.total
            if daemon is not None:
                try:
                    daemon.close()
                except OSError as exc:
                    errors_found = True
                    self.output_queue.put(f"ERROR while closing owned clamd: {exc}\n")
            if self.process is not None:
                try:
                    if self.process.poll() is None:
                        self.stop()
                    self.process.wait()
                except OSError as exc:
                    errors_found = True
                    self.output_queue.put(f"ERROR while closing scanner: {exc}\n")
                finally:
                    if self.process.stdout:
                        self.process.stdout.close()
            self.process = None
            result = {
                "infected": infected,
                "infected_found": infected_found,
                "total": total,
                "scanned": (
                    clamav_scanned_files
                    if clamav_scanned_files is not None
                    else self.scanned_files
                ),
                "stopped": self.stop_requested,
                "errors": errors_found,
                "warnings": warnings_found,
                "admin_hint": admin_hint,
                "summary_lines": scan_summary_lines,
                "parallel": used_parallel,
                'warning_counts': dict(self.warning_summary.counts),
                'warning_details': self.warning_summary.details,
                'warning_count': sum(self.warning_summary.counts.values()),
                'scan_profile': self.scan_profile,
                'uses_system_daemon': bool(daemon and daemon.reused),
            }
            self.result = result
            self.output_queue.put(("__SCAN_DONE__", result))

    def _run_parallel(self, files, endpoint, *, direct=False):
        """Keep a bounded queue and aggregate results on this worker thread."""
        infected, warnings, errors = [], False, False
        self.parallel_warnings = self.parallel_errors = 0
        paths = iter(files)
        workers = scan_limits(self.scan_profile).workers
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix='clamd-scan') as pool:
            pending = {}

            def submit():
                while len(pending) < workers and not self.stop_requested:
                    path = next(paths, None)
                    if path is None:
                        break
                    options = {'direct': True} if direct else {}
                    pending[pool.submit(scan_file, endpoint, path,
                                        lambda: self.stop_requested, **options)] = path

            submit()
            while pending:
                completed, _ = wait(pending, timeout=.2, return_when=FIRST_COMPLETED)
                for future in completed:
                    path = pending.pop(future)
                    try:
                        status = future.result()
                    except ScanCancelled:
                        continue
                    except (PermissionError, FileNotFoundError, IsADirectoryError, FileScanWarning) as exc:
                        warnings = True
                        self.parallel_warnings += 1
                        self.warning_summary.add(path, str(exc))
                        self.output_queue.put(f"{path}: {clean_reason(exc)} WARNING\n")
                    except OSError as exc:
                        # A transport or stream-limit failure is never a clean scan.
                        errors = True
                        self.parallel_errors += 1
                        self.output_queue.put(f"{path}: {exc} ERROR\n")
                    else:
                        category = alert_warning(status)
                        if category:
                            warnings = True
                            self.parallel_warnings += 1
                            self.warning_summary.add(path, status, category)
                            reason = 'scan limit reached; file was not fully checked' if category == 'limits' else 'encrypted contents could not be checked'
                            self.output_queue.put(f"{path}: {reason} WARNING\n")
                        elif status.endswith(' FOUND'):
                            infected.append((path, status))
                            self.output_queue.put(f"{path}: {status}\n")
                    self.scanned_files += 1
                    self.output_queue.put(("__CURRENT_FILE__", path))
                    progress = getattr(self, 'progress_counter', None)
                    if progress is None:
                        progress = files
                    if isinstance(progress, FileDiscovery) and not progress.done.is_set():
                        progress.notify()
                    else:
                        self.output_queue.put(("__PROGRESS__", self.scanned_files, len(progress), False))
                submit()
        return infected, warnings, errors


def scan_outcome(result):
    """One shared outcome policy; never report a failed scan as clean."""
    if result.get("stopped"):
        return "Scan stopped by user"
    if result.get("infected") or result.get("infected_found"):
        return "Infected files found!"
    if result.get("errors"):
        return "Scan failed"
    if result.get("warnings"):
        return "Scan completed — some files could not be fully checked"
    return "No threats found"
