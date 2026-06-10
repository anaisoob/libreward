"""Abstract interface for OS-specific operations.

Every platform (Linux, Windows) provides its own concrete backend.
The GUI and core logic must never branch on OS directly — they call
methods on the active backend instance.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RuntimeInfo:
    """Describes a detected ClamAV runtime installation."""

    source: str           # "bundled", "user-updated", "system-path", "none"
    clamscan: str | None  # abs path to clamscan binary
    freshclam: str | None # abs path to freshclam binary
    version: str | None   # raw version string, e.g. "ClamAV 1.5.2"
    version_num: str | None  # just the number, e.g. "1.5.2"

    @property
    def found(self) -> bool:
        return self.clamscan is not None

    @property
    def freshclam_found(self) -> bool:
        return self.freshclam is not None


class PlatformBackend(ABC):
    """Abstract interface for OS-specific operations."""

    # ── process management ──────────────────────────────────────────

    @abstractmethod
    def start_process(self, cmd, **kwargs):
        """Start a subprocess with platform-appropriate process-group handling.

        Returns a subprocess.Popen instance.
        """
        ...

    @abstractmethod
    def stop_process(self, process):
        """Gracefully terminate a process started by start_process()."""
        ...

    # ── writable data directories ───────────────────────────────────

    @abstractmethod
    def config_dir(self) -> Path:
        """Directory for config.json (per-user, writable)."""
        ...

    @abstractmethod
    def data_dir(self) -> Path:
        """Directory for runtime data (logs, DB, clamav-runtime)."""
        ...

    @abstractmethod
    def db_dir(self) -> Path | None:
        """Directory for ClamAV virus database files.

        Returns a Path if this platform manages its own database directory
        (Windows — %APPDATA%\\...\\clamav-db). Returns None on Linux,
        where the system ClamAV uses its native DB location.
        """
        ...

    @abstractmethod
    def manages_own_database(self) -> bool:
        """True if this platform manages its own DB directory (Windows).

        When False (Linux), the scanner must NOT pass --database and
        freshclam runs using the system config without a custom conf file.
        """
        ...

    @abstractmethod
    def system_db_locations(self) -> list[Path]:
        """List of system paths where ClamAV databases might live.

        Used by the health checker to detect whether a DB exists.
        On Linux: ['/var/lib/clamav'].
        On Windows: returns db_dir() if it exists.
        """
        ...

    @abstractmethod
    def log_dir(self) -> Path:
        """Directory for application log files."""
        ...

    @abstractmethod
    def updates_dir(self) -> Path:
        """Directory for update staging/download artifacts."""
        ...

    @abstractmethod
    def quarantine_dir(self) -> Path:
        """Directory for quarantined files (moved, not deleted).

        Files placed here are renamed, have their permissions stripped,
        and are accompanied by a metadata JSON for potential restore.
        """
        ...

    # ── ClamAV runtime detection ────────────────────────────────────

    @abstractmethod
    def detect_clamav_runtime(self) -> RuntimeInfo:
        """Find the best available ClamAV runtime and return RuntimeInfo."""
        ...

    @abstractmethod
    def get_clamav_version(self, clamscan_path: str) -> str | None:
        """Run clamscan --version and return the raw version string, or None."""
        ...

    @abstractmethod
    def manages_own_runtime(self) -> bool:
        """True if this platform manages its own ClamAV runtime (Windows).

        When True: the app downloads, extracts, and maintains the ClamAV
        runtime folder itself (portable ZIP from GitHub).

        When False (Linux): ClamAV is installed via the system package
        manager. The app only detects it via PATH.
        """
        ...

    @abstractmethod
    def runtime_install_instructions(self) -> str:
        """Return a human-readable string telling the user how to install
        ClamAV if it isn't found on this platform.

        Windows: explains the auto-download flow.
        Linux: shows distro-specific package manager commands.
        """
        ...

    # ── excludes ────────────────────────────────────────────────────

    @abstractmethod
    def default_common_excludes(self) -> dict[str, list[str]]:
        """Return platform-appropriate default exclude patterns.

        Keys are human-readable labels, values are lists of regex patterns
        or absolute-path prefixes.
        """
        ...

    # ── quick scan paths ───────────────────────────────────────────

    @abstractmethod
    def quick_scan_paths(self) -> list[str]:
        """Return platform-specific paths for a Quick System Scan.

        These are common locations where malware is most likely to be found:
        temp directories, downloads, browser caches, startup folders, etc.
        Only paths that currently exist on the filesystem should be returned.
        """
        ...

    # ── platform info ───────────────────────────────────────────────

    @abstractmethod
    def platform_arch(self) -> str:
        """Return a string like 'windows-x64', 'linux-x64', etc."""
        ...
