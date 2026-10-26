"""Windows platform backend.

ClamAV runtime detection order on Windows:

    1. %APPDATA%\\LibreWard\\clamav-runtime\\current\\   (user-updated, writable)
    2. <app_dir>\\runtime\\default-clamav\\                 (bundled, read-only)
    3. common system install folders, e.g. C:\\Program Files\\ClamAV
    4. system PATH (shutil.which)

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

    @staticmethod
    def _known_folder(identifier):
        """Resolve redirected/localized Windows known folders without guessing."""
        import ctypes
        import uuid
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [('Data1', wintypes.DWORD), ('Data2', wintypes.WORD),
                        ('Data3', wintypes.WORD), ('Data4', ctypes.c_ubyte * 8)]

        folder_id = GUID.from_buffer_copy(uuid.UUID(identifier).bytes_le)
        shell = ctypes.WinDLL('shell32', use_last_error=True)
        ole = ctypes.WinDLL('ole32', use_last_error=True)
        function = shell.SHGetKnownFolderPath
        function.argtypes = [ctypes.POINTER(GUID), wintypes.DWORD, wintypes.HANDLE,
                             ctypes.POINTER(ctypes.c_void_p)]
        function.restype = ctypes.c_long
        ole.CoTaskMemFree.argtypes = [ctypes.c_void_p]
        ole.CoTaskMemFree.restype = None
        result = ctypes.c_void_p()
        try:
            if function(ctypes.byref(folder_id), 0, None, ctypes.byref(result)) != 0:
                return None
            return Path(ctypes.wstring_at(result)) if result.value else None
        finally:
            if result.value:
                ole.CoTaskMemFree(result)

    def downloads_directory(self):
        try:
            return self._known_folder('374de290-123f-4565-9164-39c4925e467b') or super().downloads_directory()
        except (OSError, AttributeError):
            return super().downloads_directory()

    def desktop_directory(self):
        try:
            return self._known_folder('b4bfcc3a-db2c-424c-b029-7fe99a87c641') or super().desktop_directory()
        except (OSError, AttributeError):
            return super().desktop_directory()

    def browser_profile_locations(self):
        entries = []
        local = os.environ.get('LOCALAPPDATA')
        roaming = os.environ.get('APPDATA')
        if local:
            for label, relative in (
                ('Chrome', 'Google/Chrome/User Data'), ('Chromium', 'Chromium/User Data'),
                ('Edge', 'Microsoft/Edge/User Data'), ('Brave', 'BraveSoftware/Brave-Browser/User Data'),
                ('Vivaldi', 'Vivaldi/User Data'),
            ):
                entries.append((label, Path(local) / relative, 'chromium'))
        if roaming:
            entries.extend([
                ('Firefox', Path(roaming) / 'Mozilla/Firefox', 'firefox'),
                ('LibreWolf', Path(roaming) / 'librewolf', 'firefox'),
                ('Waterfox', Path(roaming) / 'Waterfox', 'firefox'),
                ('Floorp', Path(roaming) / 'Floorp', 'firefox'),
                ('Zen', Path(roaming) / 'zen', 'firefox'),
                ('Opera', Path(roaming) / 'Opera Software/Opera Stable', 'chromium'),
            ])
        return entries

    def send_desktop_notification(self, title, message, *, warning=False, replace=None):
        # A toast through PowerShell's registered app ID needs no tray icon or
        # COM registration. Text travels in the environment, never in the script.
        import base64
        script = r'''
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$title = [Security.SecurityElement]::Escape($env:LIBREWARD_TITLE)
$text = [Security.SecurityElement]::Escape($env:LIBREWARD_TEXT)
$scenario = if ($env:LIBREWARD_WARNING -eq '1') { " scenario='reminder'" } else { '' }
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml("<toast$scenario><visual><binding template='ToastGeneric'><text>$title</text><text>$text</text></binding></visual></toast>")
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($xml))
'''
        environment = dict(os.environ, LIBREWARD_TITLE=title, LIBREWARD_TEXT=message,
                           LIBREWARD_WARNING='1' if warning else '0')
        try:
            result = subprocess.run(
                ['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                 '-EncodedCommand', base64.b64encode(script.encode('utf-16-le')).decode('ascii')],
                env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=20,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), check=False)
            return result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def notifications_available(self):
        return shutil.which('powershell.exe') is not None

    def show_error_without_gui(self, title, message):
        import ctypes
        try:
            ctypes.windll.user32.MessageBoxW(None, message, title, 0x10)  # MB_ICONERROR
        except (AttributeError, OSError):
            pass

    def quote_argument(self, argument):
        return subprocess.list2cmdline([argument])

    def application_command(self, *arguments):
        command = super().application_command(*arguments)
        # pythonw.exe: no console window for the GUI or the background agent.
        windowless = Path(command[0]).with_name('pythonw.exe')
        if command[0].lower().endswith('python.exe') and windowless.is_file():
            command[0] = str(windowless)
        return command

    def open_application(self, *arguments, activation_token=None):
        subprocess.Popen(self.application_command(*arguments), stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)

    def acquire_instance_lock(self, path):
        import msvcrt
        path.parent.mkdir(parents=True, exist_ok=True)
        stream = open(path, 'a+', encoding='utf-8')  # noqa: SIM115 - held until the caller closes it
        try:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            stream.close()
            return None
        return stream

    RUN_KEY = r'Software\Microsoft\Windows\CurrentVersion\Run'
    RUN_VALUE = 'LibreWard Monitor'

    def monitor_service_installed(self):
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.RUN_KEY) as key:
                winreg.QueryValueEx(key, self.RUN_VALUE)
            return True
        except FileNotFoundError:
            return False

    def set_monitor_service(self, enabled):
        import winreg
        if not enabled:
            # The agent exits by itself once the saved settings turn monitoring off.
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, self.RUN_VALUE)
            except FileNotFoundError:
                pass
            return
        command = self.application_command('--monitor')
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.RUN_KEY) as key:
            winreg.SetValueEx(key, self.RUN_VALUE, 0, winreg.REG_SZ, subprocess.list2cmdline(command))
        if not self.monitor_agent_running():
            subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW)

    def clamd_endpoints(self):
        endpoints = super().clamd_endpoints()
        for folder in self._candidate_runtime_dirs():
            try:
                for line in (folder / 'clamd.conf').read_text().splitlines():
                    parts = line.strip().split()
                    if len(parts) == 2 and parts[0] == 'TCPSocket':
                        port = int(parts[1])
                        if 0 < port < 65536:
                            endpoints.insert(0, ('tcp', ('127.0.0.1', port)))
            except (OSError, ValueError, UnicodeError):
                pass
        return endpoints

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
        locations: list[Path] = []

        app_db = self.db_dir()
        if app_db.exists():
            locations.append(app_db)

        for runtime_dir in self._candidate_runtime_dirs():
            runtime_db = runtime_dir / "db"
            if runtime_db.exists() and runtime_db not in locations:
                locations.append(runtime_db)

        return locations

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

    def _system_install_dirs(self) -> list[Path]:
        """Common Windows ClamAV install directories not necessarily on PATH."""
        candidates: list[Path] = []
        for env_name in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
            base = os.environ.get(env_name)
            if base:
                candidates.append(Path(base) / "ClamAV")

        for path in (
            Path(r"C:\Program Files\ClamAV"),
            Path(r"C:\Program Files (x86)\ClamAV"),
        ):
            if path not in candidates:
                candidates.append(path)

        return candidates

    def _path_runtime_dirs(self) -> list[Path]:
        """Runtime directories discovered from PATH executables."""
        dirs: list[Path] = []
        for exe_name in ("clamscan", "clamscan.exe"):
            found = shutil.which(exe_name)
            if found:
                parent = Path(found).parent
                if parent not in dirs:
                    dirs.append(parent)
        return dirs

    def _candidate_runtime_dirs(self) -> list[Path]:
        """Runtime folders that might also contain a local db directory."""
        candidates = [self._runtime_current_dir()]
        bundled = self._bundled_runtime_dir()
        if bundled is not None:
            candidates.append(bundled)
        candidates.extend(self._system_install_dirs())
        candidates.extend(self._path_runtime_dirs())

        unique: list[Path] = []
        for path in candidates:
            if path not in unique:
                unique.append(path)
        return unique

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

        # 3 — common system install folders
        for system_dir in self._system_install_dirs():
            cs, fc = self._check_runtime_dir(system_dir)
            if cs:
                version_raw = self.get_clamav_version(cs)
                return RuntimeInfo(
                    source="system-install",
                    clamscan=cs,
                    freshclam=fc,
                    version=version_raw,
                    version_num=_parse_version(version_raw),
                )

        # 4 — system PATH fallback
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
        local_appdata = os.environ.get("LOCALAPPDATA", "")
        appdata = os.environ.get("APPDATA", "")
        programdata = os.environ.get("PROGRAMDATA", "")
        startup = os.path.join("Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        candidates = [
            # Temporary folders, where downloaded installers and droppers unpack
            os.environ.get("TEMP", ""),
            os.environ.get("TMP", ""),
            os.path.join(local_appdata, "Temp") if local_appdata else "",
            # Where files arrive; Public is writable by every user
            str(self.downloads_directory() or ""),
            str(self.desktop_directory() or ""),
            os.environ.get("PUBLIC", ""),
            # Startup folders of this user and of all users
            os.path.join(appdata, startup) if appdata else "",
            os.path.join(programdata, startup) if programdata else "",
        ]
        return [p for p in candidates if p and os.path.isdir(p)]

    RUN_KEYS = (r'Software\Microsoft\Windows\CurrentVersion\Run',
                r'Software\Microsoft\Windows\CurrentVersion\RunOnce')

    @staticmethod
    def command_arguments(command):
        """Split a Run entry; an unquoted program path may contain spaces."""
        command = os.path.expandvars(command.strip())
        if command.startswith('"'):
            program, _quote, rest = command[1:].partition('"')
            return [program, *rest.split()]
        parts = command.split()
        for end in range(len(parts), 0, -1):
            if os.path.isfile(' '.join(parts[:end])):
                return [' '.join(parts[:end]), *parts[end:]]
        return parts

    def autostart_programs(self) -> list[str]:
        """Programs started at login by the Run and RunOnce registry entries."""
        import winreg
        files = []
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            for path in self.RUN_KEYS:
                try:
                    key = winreg.OpenKey(hive, path)
                except OSError:
                    continue
                with key:
                    index = 0
                    while True:
                        try:
                            _name, value, kind = winreg.EnumValue(key, index)
                        except OSError:
                            break
                        index += 1
                        if kind in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) and isinstance(value, str):
                            files += self.command_files(self.command_arguments(value))
        return list(dict.fromkeys(files))

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

    def scan_may_need_admin(self, scan_roots) -> bool:
        """True when a Windows scan target is commonly protected."""
        roots = [scan_roots] if isinstance(scan_roots, str) else list(scan_roots)
        windir = os.path.abspath(os.environ.get("WINDIR", r"C:\Windows")).lower()
        program_files = [
            os.path.abspath(path).lower()
            for path in (
                os.environ.get("ProgramFiles"),
                os.environ.get("ProgramFiles(x86)"),
                os.environ.get("ProgramW6432"),
            )
            if path
        ]

        for root in roots:
            root_abs = os.path.abspath(root).lower()
            drive, tail = os.path.splitdrive(root_abs)
            if drive and tail in ("\\", "/"):
                return True
            if root_abs == windir or root_abs.startswith(windir + os.sep):
                return True
            if any(
                root_abs == pf or root_abs.startswith(pf + os.sep)
                for pf in program_files
            ):
                return True

        return False
