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


def newest_database_time(directory):
    """Modification time of the newest ClamAV database file, or None."""
    try:
        times = [path.stat().st_mtime for path in Path(directory).iterdir()
                 if path.suffix.lower() in ('.cvd', '.cld', '.cud')]
    except OSError:
        return None
    return max(times) if times else None


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

        Windows always; Linux uses its own database when the system one is
        missing or stale (see LinuxBackend.system_db_locations).
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

    def scan_may_need_admin(self, scan_roots) -> bool:
        """Whether selected targets warrant an optional deeper-scan hint."""
        return False

    def clamd_endpoints(self):
        """Local daemon endpoints: ('unix', path) or ('tcp', (host, port))."""
        return [("tcp", ("127.0.0.1", 3310))]

    def get_freshclam_version(self, freshclam_path):
        return self.get_clamav_version(freshclam_path)

    def system_database_current(self):
        """True when a system-maintained virus database is up to date."""
        return False

    def find_clamd(self, clamscan_path):
        """Find a daemon in the detected runtime, without downloading anything."""
        import shutil
        executable = "clamd.exe" if str(clamscan_path).lower().endswith(".exe") else "clamd"
        sibling = Path(clamscan_path).parent / executable
        return str(sibling) if sibling.is_file() else shutil.which(executable)

    def clamd_listen_config(self, work_dir):
        """Generate a private local listener for an application-owned daemon."""
        import socket
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        return ("tcp", ("127.0.0.1", port)), ["TCPAddr 127.0.0.1", f"TCPSocket {port}"]

    def inspect_firewall(self, *, privileged=False, tool_name=None):
        """Read firewall state without changing rules or requesting privileges."""
        from core.firewall import FirewallSnapshot
        return FirewallSnapshot()

    def firewall_change_preview(self, tool_name, *, rule=None, enabled=True):
        raise NotImplementedError('Firewall changes are not available on this platform.')

    def change_firewall(self, tool_name, *, rule=None, enabled=True, removal=None):
        raise NotImplementedError('Firewall changes are not available on this platform.')

    def firewall_networks(self):
        """Connected LAN candidates as (interface, CIDR) pairs."""
        return []

    def authorization_status(self):
        from core.authorization import AuthorizationStatus
        return AuthorizationStatus(False, 'System authorization is unavailable on this platform.')

    def clamav_install_plan(self):
        """Optional distro package installation plan, separate from Windows runtime updates."""
        return None

    def install_clamav(self, log=None):
        raise NotImplementedError('Use the platform installation instructions.')

    def freshclam_activity(self):
        """Existing system updater description, or None when not detected."""
        return None

    def inspect_internet_protection(self):
        return {'supported': False, 'active': False, 'count': 0,
                'message': 'Domain protection is currently available on Linux only.'}

    def apply_internet_protection(self, domains, upstream=None):
        raise NotImplementedError('Domain protection is currently available on Linux only.')

    def reset_cancellation(self):
        """Start of a cancellable operation; forget earlier cancel requests."""

    def cancel_authorization(self):
        """Stop a privileged helper that is still waiting for the password; True if stopped."""
        return False

    def internet_protection_available(self):
        """Whether this platform offers Internet protection at all (cheap, no checks)."""
        return False

    def internet_protection_state_directory(self):
        """Directory whose changes mean the protection state changed, or None."""
        return None

    def internet_protection_enabled(self):
        """Cheap check, without probing DNS: is the protection service switched on?"""
        return False

    def downloads_directory(self):
        """Configured system Downloads folder, or None when disabled."""
        return Path.home() / 'Downloads'

    def desktop_directory(self):
        return Path.home() / 'Desktop'

    def user_directories_file(self):
        """File naming the system Downloads folder, when the platform has one."""
        return None

    def browser_profile_locations(self):
        """(Browser label, configuration root, 'chromium' or 'firefox')."""
        return []

    def folder_observer(self):
        """Native recursive filesystem notifications for this platform."""
        from watchdog.observers import Observer
        return Observer()

    def send_desktop_notification(self, title, message, *, warning=False, on_open=None):
        """Send without a tray; called from a worker. True when the desktop accepted it.

        `on_open`, when given, adds an "Open LibreWard" action. It is called from a
        background thread with the desktop's activation token (or None) when the
        user chooses it; the token lets the opened window come to the front.
        """
        return False

    def notifications_available(self):
        """Whether send_desktop_notification can reach the desktop at all."""
        return False

    def show_error_without_gui(self, title, message):
        """Last-resort message when the Qt interface itself cannot start."""

    # ── dependencies ────────────────────────────────────────────────

    def quote_argument(self, argument):
        import shlex
        return shlex.quote(argument)

    def python_requirements_command(self):
        """Install the Python dependencies into the interpreter running LibreWard."""
        import shutil
        import sys
        root = Path(__file__).resolve().parent.parent
        if (root / 'uv.lock').is_file() and shutil.which('uv'):
            return f'cd {self.quote_argument(str(root))} && uv sync'
        return (f'{self.quote_argument(sys.executable)} -m pip install -r '
                f'{self.quote_argument(str(root / "requirements.txt"))}')

    def dependency_install_commands(self, components):
        """Commands installing components ('pyside6', 'qtnetwork', 'watchdog', 'notify-send')."""
        from core.dependencies import PYTHON_MODULES
        return [self.python_requirements_command()] if any(c in PYTHON_MODULES for c in components) else []

    # ── folder monitoring agent ─────────────────────────────────────

    def application_command(self, *arguments):
        """Command that starts this LibreWard installation (source or package)."""
        import sys
        if getattr(sys, 'frozen', False):
            return [sys.executable, *arguments]
        main = Path(__file__).resolve().parent.parent / 'main.py'
        # -s and -E, like the installed launcher: user site-packages and PYTHON*
        # variables cannot replace application modules.
        return [sys.executable, '-s', '-E', str(main), *arguments]

    def application_environment(self):
        """Environment for starting the GUI from the background agent."""
        import os
        return dict(os.environ)

    def open_application(self, *arguments, activation_token=None):
        """Start the GUI; a running window comes to the front instead."""
        import subprocess
        environment = self.application_environment()
        if activation_token:
            # Wayland (xdg-activation) and X11 startup notification use the same token.
            environment.update(XDG_ACTIVATION_TOKEN=activation_token, DESKTOP_STARTUP_ID=activation_token)
        subprocess.Popen(self.application_command(*arguments), env=environment, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)

    @abstractmethod
    def acquire_instance_lock(self, path):
        """Exclusive lock held until the returned file is closed; None when taken."""
        ...

    def instance_running(self, path):
        """True while another process holds the instance lock at `path`."""
        try:
            lock = self.acquire_instance_lock(path)
        except OSError:
            return False
        if lock is None:
            return True
        lock.close()
        return False

    def monitor_agent_running(self):
        """True while a monitoring agent of this user holds its lock."""
        from core.monitor_agent import lock_file
        return self.instance_running(lock_file())

    def gui_running(self):
        """True while a LibreWard window of this user is open."""
        from core.monitor_agent import gui_lock_file
        return self.instance_running(gui_lock_file())

    def monitor_service_installed(self):
        """Whether the login entry of the agent exists (removed by Turn off or uninstall)."""
        return False

    def set_monitor_service(self, enabled):
        """Start the agent at login and now, or remove it. Raises OSError with a message."""
        raise OSError('Background folder monitoring is not available on this platform.')

    def remove_autostart(self):
        """Remove a login autostart entry written by an earlier LibreWard version."""
