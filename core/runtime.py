"""Central ClamAV runtime detection and health checking.

This module wraps the platform backend's runtime detection with
convenience functions used by both the GUI and the updater.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from backends import backend, RuntimeInfo


# ── startup check ───────────────────────────────────────────────────

@dataclass
class StartupStatus:
    """Result of the startup health check."""

    runtime: RuntimeInfo
    runtime_ok: bool        # clamscan found and --version works
    db_found: bool          # at least one .cvd/.cld file exists in db_dir
    db_needs_update: bool   # db_found but possibly stale (always True for now)
    freshclam_ok: bool      # freshclam found and --version works
    clamd_path: str | None = None
    clamd_running: bool = False

    @property
    def can_scan(self) -> bool:
        """Can we start a scan right now?"""
        return self.runtime_ok and self.db_found

    @property
    def can_update_db(self) -> bool:
        """Can we run freshclam to update the database?"""
        return self.freshclam_ok

    @property
    def is_first_run(self) -> bool:
        """Is this a first-run with no ClamAV at all?"""
        return not self.runtime.found


def check_startup(log: Callable[[str], None] | None = None) -> StartupStatus:
    """Perform the startup health check.

    Call this once when the app starts. Pass a log callback to
    emit progress messages to the GUI.
    """
    if log:
        log("Checking ClamAV runtime...\n")

    runtime = backend.detect_clamav_runtime()

    if log:
        if runtime.found:
            log(f"  clamscan:   {runtime.clamscan}\n")
            if runtime.version:
                log(f"  version:    {runtime.version}\n")
            else:
                log("  version:    unavailable (clamscan --version failed)\n")
            log(f"  source:     {runtime.source}\n")
        else:
            log("  No ClamAV runtime found.\n")

    # Runtime OK?
    runtime_ok = runtime.found and runtime.version is not None

    # Database check
    db_found = False
    db_locations = backend.system_db_locations()
    for loc in db_locations:
        if _check_database_dir(loc):
            db_found = True
            db_dir = loc
            break
    else:
        db_dir = None

    if log:
        if db_found:
            log(f"  Database:   found in {db_dir}\n")
        elif db_locations:
            log(f"  Database:   not found (checked {', '.join(str(d) for d in db_locations)})\n")
        else:
            log("  Database:   not found\n")

    # Freshclam check
    freshclam_ok = False
    if runtime.freshclam:
        fc_version = backend.get_clamav_version(runtime.freshclam)
        freshclam_ok = fc_version is not None
        if log:
            if freshclam_ok:
                log(f"  freshclam:  {runtime.freshclam}\n")
            else:
                log(f"  freshclam:  {runtime.freshclam} (version check failed)\n")

    # Probe only: checking status must never start a daemon or download files.
    from core.clamd import ping
    clamd_path = backend.find_clamd(runtime.clamscan) if runtime.clamscan else None
    clamd_running = any(ping(endpoint) for endpoint in backend.clamd_endpoints())
    if log:
        log(f"  Parallel scanner: {'running' if clamd_running else 'installed (starts when needed)' if clamd_path else 'not installed'}\n")

    return StartupStatus(
        runtime=runtime,
        runtime_ok=runtime_ok,
        db_found=db_found,
        db_needs_update=not db_found,
        freshclam_ok=freshclam_ok,
        clamd_path=clamd_path,
        clamd_running=clamd_running,
    )


def setup_components(status):
    """User-facing readiness, independent of the GUI and operating system."""
    return [
        ('Antivirus engine', 'Ready' if status.runtime_ok else 'Installation required'),
        ('Database updater', 'Ready' if status.freshclam_ok else 'Installation required'),
        ('Virus database', 'Available' if status.db_found else 'Download required'),
        ('Parallel scanner', 'Running' if status.clamd_running else
         'Installed — starts when needed' if status.clamd_path else 'Optional installation available'),
    ]


def setup_next_action(status):
    if not status.runtime_ok or not status.freshclam_ok:
        return 'runtime', 'Install ClamAV'
    if not status.db_found:
        return 'database', 'Download virus database'
    if not (status.clamd_path or status.clamd_running):
        return 'runtime', 'Set up parallel scanning'
    return 'ready', 'Done'


# ── version comparison ──────────────────────────────────────────────

def _version_tuple(ver: str | None) -> tuple[int, ...]:
    """Convert a version string like '1.5.2' to a comparable tuple."""
    if not ver:
        return (0,)
    try:
        return tuple(int(x) for x in ver.split("."))
    except (ValueError, TypeError):
        return (0,)


def is_newer_version(new_ver: str | None, current_ver: str | None) -> bool:
    """Return True if new_ver > current_ver."""
    return _version_tuple(new_ver) > _version_tuple(current_ver)


# ── database helpers ────────────────────────────────────────────────

def _check_database_dir(db_dir: Path) -> bool:
    """Check if at least one ClamAV database file exists in the directory."""
    try:
        if not db_dir.is_dir():
            return False
        for entry in db_dir.iterdir():
            if entry.suffix.lower() in (".cvd", ".cld"):
                return True
    except OSError:
        pass
    return False


def database_files(db_dir: Path | None = None) -> list[str]:
    """Return a list of database filenames found.

    If db_dir is not provided, checks all system_db_locations()
    and returns files from the first location that has any.
    """
    if db_dir is not None:
        return _list_db_files(db_dir)
    for loc in backend.system_db_locations():
        files = _list_db_files(loc)
        if files:
            return files
    return []


def _list_db_files(db_dir: Path) -> list[str]:
    try:
        if not db_dir.is_dir():
            return []
        return sorted(
            p.name for p in db_dir.iterdir()
            if p.suffix.lower() in (".cvd", ".cld")
        )
    except OSError:
        return []


# ── runtime lock ────────────────────────────────────────────────────

def _lock_path() -> Path:
    return backend.data_dir() / "runtime-update.lock"


def is_update_locked() -> bool:
    return _lock_path().exists()


def create_update_lock() -> None:
    backend.data_dir().mkdir(parents=True, exist_ok=True)
    _lock_path().write_text("locked")


def release_update_lock() -> None:
    try:
        _lock_path().unlink(missing_ok=True)
    except OSError:
        pass
