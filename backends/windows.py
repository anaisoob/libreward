"""Windows platform backend.

ClamAV runtime detection order on Windows:

    1. %APPDATA%\\LibreWard\\clamav-runtime\\current\\   (user-updated, writable)
    2. <app_dir>\\runtime\\default-clamav\\                 (bundled, read-only)
    3. system PATH (shutil.which)

Only #1 and #2 provide a full runtime folder. PATH lookup is a fallback
that may yield just clamscan.exe without its required DLLs.
"""

import os
import platform as _platform
import re
import shutil
import subprocess
from pathlib import Path

from core.constants import CLAMAV_DB_MIRROR
from .base import PlatformBackend, RuntimeInfo


APP_NAME = "LibreWard"


def _parse_version(raw: str | None) -> str | None:
    """Extract version number from clamscan --version output.

    Example input:  "ClamAV 1.5.2"
    Returns:        "1.5.2"
    """
    if not raw:
        return None
    m = re.search(r"(\d+\.\d+\.\d+)", raw)
    return m.group(1) if m else None


class WindowsBackend(PlatformBackend):
    """Platform backend for Windows."""

    # ── process management ──────────────────────────────────────────

    def start_process(self, cmd, **kwargs):
        flags = kwargs.pop("creationflags", 0)
        flags |= subprocess.CREATE_NEW_PROCESS_GROUP
        self._apply_runtime_process_context(cmd, kwargs)
        return subprocess.Popen(cmd, creationflags=flags, **kwargs)

    def stop_process(self, process):
        if process.poll() is None:
            process.terminate()

    # ── writable data directories ───────────────────────────────────

    def config_dir(self) -> Path:
        return Path(os.environ["APPDATA"]) / APP_NAME

    def data_dir(self) -> Path:
        return Path(os.environ["APPDATA"]) / APP_NAME

    def db_dir(self) -> Path:
        return self.data_dir() / "clamav-db"

    def manages_own_database(self) -> bool:
        return True

    def system_db_locations(self) -> list[Path]:
        db = self.db_dir()
        return [db] if db.exists() else []

    def log_dir(self) -> Path:
        return self.data_dir() / "logs"

    def updates_dir(self) -> Path:
        return self.data_dir() / "updates"

    def quarantine_dir(self) -> Path:
        return self.data_dir() / "quarantine"

    # ── ClamAV runtime detection ────────────────────────────────────

    def _app_dir(self) -> Path | None:
        """Return the directory containing the application entry point."""
        try:
            import __main__
            main_file = getattr(__main__, "__file__", None)
            if main_file:
                return Path(main_file).resolve().parent
        except Exception:
            pass
        return None

    def _runtime_current_dir(self) -> Path:
        """%APPDATA%\\LibreWard\\clamav-runtime\\current\\"""
        return self.data_dir() / "clamav-runtime" / "current"

    def _runtime_previous_dir(self) -> Path:
        """%APPDATA%\\LibreWard\\clamav-runtime\\previous\\"""
        return self.data_dir() / "clamav-runtime" / "previous"

    def _bundled_runtime_dir(self) -> Path | None:
        """<app_dir>\\runtime\\default-clamav\\"""
        app_dir = self._app_dir()
        if app_dir is None:
            return None
        return app_dir / "runtime" / "default-clamav"

    def _check_runtime_dir(self, directory: Path) -> tuple[str | None, str | None]:
        """Check a directory for clamscan.exe and freshclam.exe.

        Returns (clamscan_path, freshclam_path) — None for each if not found.
        """
        clamscan = directory / "clamscan.exe"
        freshclam = directory / "freshclam.exe"
        return (
            str(clamscan) if clamscan.is_file() else None,
            str(freshclam) if freshclam.is_file() else None,
        )

    def _apply_runtime_process_context(self, cmd, kwargs: dict) -> None:
        """Run portable runtime executables from their folder with PATH set.

        Some Windows DLL resolution paths depend on the process working
        directory or PATH. Prefixing the executable folder makes downloaded
        portable ClamAV runtimes behave like a normal unpacked command prompt.
        """
        if not cmd:
            return

        exe = Path(str(cmd[0]))
        if not exe.is_file():
            return

        runtime_dir = str(exe.parent)
        kwargs.setdefault("cwd", runtime_dir)

        env = dict(kwargs.get("env") or os.environ)
        path_key = next((k for k in env if k.upper() == "PATH"), "PATH")
        existing_path = env.get(path_key, "")
        path_parts = existing_path.split(os.pathsep) if existing_path else []
        if runtime_dir not in path_parts:
            env[path_key] = runtime_dir + (
                os.pathsep + existing_path if existing_path else ""
            )
        kwargs["env"] = env

    def _ensure_freshclam_conf(self) -> str | None:
        """Create the managed Windows freshclam.conf if needed."""
        db_dir = self.db_dir()
        db_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir().mkdir(parents=True, exist_ok=True)

        conf_path = self.data_dir() / "freshclam.conf"
        db_dir_str = str(db_dir.resolve())
        log_file = str((self.log_dir() / "freshclam.log").resolve())

        content = [
            "# Generated by LibreWard",
            "# Updates go to the app-data directory, never inside the runtime folder.",
            f"DatabaseDirectory {db_dir_str}",
            f"UpdateLogFile {log_file}",
            f"DatabaseMirror {CLAMAV_DB_MIRROR}",
            "",
            "MaxAttempts 3",
            "ConnectTimeout 30",
            "ReceiveTimeout 60",
            "Foreground yes",
            "ScriptedSecurity yes",
            "Checks 1",
            "LogVerbose no",
        ]
        conf_path.write_text("\n".join(content), encoding="utf-8")
        return str(conf_path)

    def detect_clamav_runtime(self) -> RuntimeInfo:
        """Find the best available ClamAV runtime (Windows order)."""

        # 1 — user-updated runtime in %APPDATA%
        current_dir = self._runtime_current_dir()
        cs, fc = self._check_runtime_dir(current_dir)
        if cs:
            version_raw = self.get_clamav_version(cs)
            return RuntimeInfo(
                source="user-updated",
                clamscan=cs,
                freshclam=fc,
                version=version_raw,
                version_num=_parse_version(version_raw),
            )

        # 2 — bundled runtime next to the app
        bundled = self._bundled_runtime_dir()
        if bundled is not None:
            cs, fc = self._check_runtime_dir(bundled)
            if cs:
                version_raw = self.get_clamav_version(cs)
                return RuntimeInfo(
                    source="bundled",
                    clamscan=cs,
                    freshclam=fc,
                    version=version_raw,
                    version_num=_parse_version(version_raw),
                )

        # 3 — system PATH fallback
        cs = shutil.which("clamscan")
        fc = shutil.which("freshclam")
        if cs:
            version_raw = self.get_clamav_version(cs)
            return RuntimeInfo(
                source="system-path",
                clamscan=cs,
                freshclam=fc,
                version=version_raw,
                version_num=_parse_version(version_raw),
            )

        return RuntimeInfo(
            source="none",
            clamscan=None,
            freshclam=None,
            version=None,
            version_num=None,
        )

    def get_clamav_version(self, clamscan_path: str) -> str | None:
        exe_path = Path(clamscan_path)
        cmd = [str(exe_path), "--version"]

        if exe_path.name.lower() == "freshclam.exe":
            conf_path = self._ensure_freshclam_conf()
            if conf_path:
                cmd = [str(exe_path), "--config-file", conf_path, "--version"]

        kwargs = {
            "capture_output": True,
            "text": True,
            "timeout": 10,
        }
        self._apply_runtime_process_context(cmd, kwargs)
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

        try:
            result = subprocess.run(cmd, **kwargs)
            if result.returncode == 0:
                return result.stdout.strip().split("\n")[0]
        except Exception:
            pass
        return None

    def manages_own_runtime(self) -> bool:
        return True

    def runtime_install_instructions(self) -> str:
        return (
            "LibreWard can download and install the official ClamAV\n"
            "command-line tools automatically.\n\n"
            "Click 'Download ClamAV' to proceed."
        )

    # ── excludes ────────────────────────────────────────────────────

    def default_common_excludes(self) -> dict[str, list[str]]:
        return {
            "Python virtual environments (.venv, venv, env)": [
                r"(^|/)\.venv($|/)",
                r"(^|/)venv($|/)",
                r"(^|/)env($|/)",
            ],
            "Python cache dirs (__pycache__, .pytest_cache, .mypy_cache, .ruff_cache)": [
                r"(^|/)__pycache__($|/)",
                r"(^|/)\.pytest_cache($|/)",
                r"(^|/)\.mypy_cache($|/)",
                r"(^|/)\.ruff_cache($|/)",
            ],
            "Node.js dependencies (node_modules)": [
                r"(^|/)node_modules($|/)",
            ],
            "Git directories (.git)": [
                r"(^|/)\.git($|/)",
            ],
            "Windows recycle bin": [
                r"(^|/)\$RECYCLE\.BIN($|/)",
            ],
            "System Volume Information": [
                r"(^|/)System Volume Information($|/)",
            ],
        }

    # ── quick scan paths ───────────────────────────────────────────

    def quick_scan_paths(self) -> list[str]:
        """Return Windows-specific quick scan paths."""
        home = os.path.expanduser("~")
        local_appdata = os.environ.get("LOCALAPPDATA", "")
        appdata = os.environ.get("APPDATA", "")
        windir = os.environ.get("WINDIR", "C:\\Windows")

        candidates = [
            # Temp directories — #1 malware location on Windows
            os.environ.get("TEMP", ""),
            os.environ.get("TMP", ""),
            os.path.join(windir, "Temp"),
            os.path.join(local_appdata, "Temp") if local_appdata else "",
            # User folders
            os.path.join(home, "Downloads"),
            os.path.join(home, "Desktop"),
            # Perzistencija — startup folder
            os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup") if appdata else "",
            # Roaming appdata (common malware hiding spot)
            appdata,
            # Browser cache / profiles
            os.path.join(local_appdata, "Google", "Chrome", "User Data") if local_appdata else "",
            os.path.join(local_appdata, "Microsoft", "Edge", "User Data") if local_appdata else "",
            os.path.join(appdata, "Mozilla", "Firefox") if appdata else "",
            os.path.join(local_appdata, "BraveSoftware", "Brave-Browser", "User Data") if local_appdata else "",
        ]
        return [p for p in candidates if p and os.path.isdir(p)]

    # ── platform info ───────────────────────────────────────────────

    def platform_arch(self) -> str:
        machine = _platform.machine().lower()
        if machine in ("amd64", "x86_64", "em64t"):
            arch = "x64"
        elif machine in ("i386", "i686", "x86"):
            arch = "x86"
        elif machine in ("arm64", "aarch64"):
            arch = "arm64"
        else:
            arch = machine
        return f"windows-{arch}"
