"""Scan orchestration: file collection, command building, output parsing."""

import os

from backends import backend
from excludes import path_is_excluded, build_clamscan_exclude_args


def collect_files(scan_roots, exclude_patterns, check_stop):
    """Walk one or more *scan_roots*, skip excluded paths, return list of file paths.

    *scan_roots* may be a single path string or a list of path strings.
    *check_stop* is a callable that returns True when scanning should abort early.
    """
    if isinstance(scan_roots, str):
        scan_roots = [scan_roots]

    files = []
    for scan_root in scan_roots:
        scan_root_abs = os.path.abspath(scan_root)
        if not os.path.isdir(scan_root_abs):
            continue

        for root, dirs, filenames in os.walk(scan_root_abs):
            if check_stop():
                return files

            root_abs = os.path.abspath(root)

            kept_dirs = []
            for dirname in dirs:
                dir_path = os.path.join(root_abs, dirname)
                if not path_is_excluded(dir_path, exclude_patterns):
                    kept_dirs.append(dirname)

            dirs[:] = kept_dirs

            if path_is_excluded(root_abs, exclude_patterns):
                dirs[:] = []
                continue

            for filename in filenames:
                full_path = os.path.join(root_abs, filename)

                try:
                    if os.path.isfile(full_path):
                        files.append(os.path.abspath(full_path))
                except OSError:
                    continue

    return files


def build_clamscan_command(scan_roots, exclude_patterns, clamscan_path=None):
    """Build the clamscan command-line argument list.

    *scan_roots* may be a single path string or a list of path strings.
    Uses *clamscan_path* if provided; otherwise resolves from the backend.
    """
    if isinstance(scan_roots, str):
        scan_roots = [scan_roots]

    if clamscan_path is None:
        runtime = backend.detect_clamav_runtime()
        if not runtime.found:
            raise FileNotFoundError("clamscan not found")
        clamscan_path = runtime.clamscan

    cmd = [
        clamscan_path,
        "-r",
        "--verbose",
        "--scan-archive=yes",
        "--alert-encrypted=yes",
    ]

    # Only pass --database on platforms that manage their own DB (Windows).
    # On Linux, the system clamscan already knows where the database lives.
    if backend.manages_own_database():
        db_dir = backend.db_dir()
        if db_dir is not None and db_dir.exists() and any(db_dir.iterdir()):
            cmd.append(f"--database={str(db_dir.resolve())}")

    cmd.extend(build_clamscan_exclude_args(exclude_patterns))
    for root in scan_roots:
        cmd.append(os.path.abspath(root))

    return cmd


def parse_clamscan_result_line(line, known_files):
    """Parse one line of clamscan --verbose output.

    Returns (path, status) if the line names a file in *known_files*,
    otherwise returns (None, None).
    """
    stripped = line.strip()

    if ": " not in stripped:
        return None, None

    candidate, status = stripped.rsplit(": ", 1)
    candidate_abs = os.path.abspath(candidate)

    if candidate_abs in known_files:
        return candidate_abs, status

    return None, None


def should_log_line(line, summary_started):
    """Decide whether a non-result output line should be shown in the log.

    Returns (should_log: bool, new_summary_started: bool).
    """
    stripped = line.strip()

    if not stripped:
        return False, summary_started

    if "FOUND" in stripped:
        return True, summary_started

    if "ERROR" in stripped:
        return True, summary_started

    if "WARNING" in stripped:
        return True, summary_started

    if "Encrypted" in stripped or "encrypted" in stripped:
        return True, summary_started

    if stripped.startswith("----------- SCAN SUMMARY -----------"):
        return True, True

    if summary_started:
        return True, True

    return False, summary_started
