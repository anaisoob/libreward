"""Linux platform backend.

ClamAV runtime detection order on Linux:

    1. system PATH (shutil.which) — standard ClamAV installation
    2. (No bundled/user-updated runtime on Linux in the initial version)

The backend still exposes the same data directory interface so that
future versions can support self-updating runtime on Linux too.
"""

import os
import platform as _platform
import re
import shutil
import signal
import subprocess
from pathlib import Path

from .base import PlatformBackend, RuntimeInfo


APP_NAME = "libreward"


def _parse_version(raw: str | None) -> str | None:
    """Extract version number from clamscan --version output."""
    if not raw:
        return None
    m = re.search(r"(\d+\.\d+\.\d+)", raw)
    return m.group(1) if m else None


class LinuxBackend(PlatformBackend):
    """Platform backend for Linux."""

    def clamd_endpoints(self):
        endpoints = [("unix", path) for path in (
            "/run/clamav/clamd.ctl", "/run/clamd.scan/clamd.sock",
            "/run/clamd/clamd.sock", "/tmp/clamd.socket")]
        for config in (Path('/etc/clamav/clamd.conf'), Path('/etc/clamd.d/scan.conf')):
            try:
                for line in config.read_text().splitlines():
                    parts = line.strip().split(maxsplit=1)
                    if len(parts) == 2 and parts[0] == 'LocalSocket':
                        endpoints.insert(0, ('unix', parts[1].strip('"')))
                    elif len(parts) == 2 and parts[0] == 'TCPSocket':
                        port = int(parts[1])
                        if 0 < port < 65536:
                            endpoints.insert(0, ('tcp', ('127.0.0.1', port)))
            except (OSError, ValueError, UnicodeError):
                pass
        return endpoints + super().clamd_endpoints()

    def clamd_listen_config(self, work_dir):
        path = str(work_dir / 'clamd.sock')
        return ('unix', path), [f'LocalSocket {path}', 'LocalSocketMode 600']

    # ── process management ──────────────────────────────────────────

    def start_process(self, cmd, **kwargs):
        kwargs.setdefault("preexec_fn", os.setsid)
        return subprocess.Popen(cmd, **kwargs)

    def stop_process(self, process):
        if process.poll() is None:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)

    # ── writable data directories ───────────────────────────────────

    def config_dir(self) -> Path:
        xdg_config = os.environ.get("XDG_CONFIG_HOME",
                                     os.path.join(os.path.expanduser("~"), ".config"))
        return Path(xdg_config) / APP_NAME

    def data_dir(self) -> Path:
        xdg_data = os.environ.get("XDG_DATA_HOME",
                                   os.path.join(os.path.expanduser("~"), ".local", "share"))
        return Path(xdg_data) / APP_NAME

    def db_dir(self) -> Path | None:
        """Linux does not manage its own database — ClamAV uses its
        system-wide database directory (e.g. /var/lib/clamav)."""
        return None

    def manages_own_database(self) -> bool:
        return False

    def system_db_locations(self) -> list[Path]:
        return [Path("/var/lib/clamav")]

    def log_dir(self) -> Path:
        return self.data_dir() / "logs"

    def updates_dir(self) -> Path:
        return self.data_dir() / "updates"

    def quarantine_dir(self) -> Path:
        return self.data_dir() / "quarantine"

    # ── ClamAV runtime detection ────────────────────────────────────

    def detect_clamav_runtime(self) -> RuntimeInfo:
        """Find ClamAV via system PATH."""
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
        try:
            result = subprocess.run(
                [clamscan_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip().split("\n")[0]
        except Exception:
            pass
        return None

    def manages_own_runtime(self) -> bool:
        return False

    def runtime_install_instructions(self) -> str:
        distro = self.distro_info()

        if distro["unknown"] == "true":
            return (
                "Could not identify your Linux distribution.\n\n"
                "Please install ClamAV using your system's package manager.\n"
                "Common package names:\n"
                "  • Debian/Ubuntu:  clamav clamav-freshclam clamav-daemon\n"
                "  • Fedora/RHEL:    clamav clamav-update clamd\n"
                "  • Arch/Manjaro:   clamav\n"
                "  • openSUSE:       clamav\n"
                "  • Gentoo:         app-antivirus/clamav\n"
                "  • Alpine:         clamav clamav-daemon\n\n"
                "After installing, use Check status in LibreWard."
            )

        lines = [
            f"Detected: {distro['name']}"
        ]
        if distro["version"]:
            lines.append(f"Version:  {distro['version']}")

        lines.extend([
            "",
            "To install ClamAV, open a terminal and run:",
            "",
            f"  {distro['install_cmd']}",
            "",
            "After installation, use Check status in LibreWard.",
            "The daemon provides optional parallel scanning. LibreWard reuses",
            "a running local daemon or starts the installed daemon when needed.",
            "",
            "Your package manager will also handle ClamAV updates.",
        ])

        return "\n".join(lines)

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
            "Node.js dependencies/cache (node_modules, .npm)": [
                r"(^|/)node_modules($|/)",
                r"(^|/)\.npm($|/)",
            ],
            "Rust cache/build dirs (target, .cargo)": [
                r"(^|/)target($|/)",
                r"(^|/)\.cargo($|/)",
            ],
            "Git directories (.git)": [
                r"(^|/)\.git($|/)",
            ],
            "General cache dirs (.cache)": [
                r"(^|/)\.cache($|/)",
            ],
            "Podman rootless internal storage": [
                os.path.join(
                    os.path.expanduser("~"), ".local/share/containers/storage"
                ),
            ],
        }

    # ── quick scan paths ───────────────────────────────────────────

    def quick_scan_paths(self) -> list[str]:
        """Return Linux-specific quick scan paths."""
        home = os.path.expanduser("~")
        candidates = [
            # Temp / shared memory (common malware staging)
            "/tmp",
            "/var/tmp",
            "/dev/shm",
            # User-writable common locations
            os.path.join(home, "Downloads"),
            os.path.join(home, "Desktop"),
            os.path.join(home, ".cache"),
            # Perzistencija
            os.path.join(home, ".config", "autostart"),
            # Trash
            os.path.join(home, ".local", "share", "Trash"),
            # Browser caches
            os.path.join(home, ".cache", "mozilla"),
            os.path.join(home, ".config", "chromium"),
            os.path.join(home, ".config", "google-chrome"),
            os.path.join(home, ".config", "microsoft-edge"),
            os.path.join(home, ".cache", "BraveSoftware"),
            # Snap tmp area (if it exists)
            os.path.join(home, "snap"),
        ]
        return [p for p in candidates if os.path.isdir(p)]

    # ── platform info ───────────────────────────────────────────────

    def platform_arch(self) -> str:
        machine = _platform.machine().lower()
        if machine in ("x86_64", "amd64"):
            arch = "x64"
        elif machine in ("i386", "i686"):
            arch = "x86"
        elif machine in ("aarch64", "arm64"):
            arch = "arm64"
        else:
            arch = machine
        return f"linux-{arch}"

    # ── distro detection & install instructions ─────────────────────

    def distro_info(self) -> dict[str, str]:
        """Detect the Linux distribution.

        Returns a dict with keys:
          id            — short distro ID (arch, ubuntu, fedora, debian, ...)
          name          — human-readable name (Arch Linux, Ubuntu, ...)
          version       — version string if available
          pkg_manager   — primary package manager (pacman, apt, dnf, zypper, ...)
          install_cmd   — command to install ClamAV (sudo pacman -S clamav)
          update_cmd    — command to update all packages (sudo pacman -Syu)
          unknown       — "true" if detection failed
        """
        # Parse /etc/os-release (exists on most modern distros)
        os_release = self._read_os_release()

        distro_id = os_release.get("ID", "")
        id_like = os_release.get("ID_LIKE", "")
        name = os_release.get("NAME", "")
        version = os_release.get("VERSION_ID", "")

        # Map distro ID to package manager commands
        pkg_map: dict[str, dict[str, str]] = {
            "arch": {
                "pkg_manager": "pacman",
                "install_cmd": "sudo pacman -S clamav",
                "update_cmd": "sudo pacman -Syu",
            },
            "manjaro": {
                "pkg_manager": "pacman",
                "install_cmd": "sudo pacman -S clamav",
                "update_cmd": "sudo pacman -Syu",
            },
            "endeavouros": {
                "pkg_manager": "pacman",
                "install_cmd": "sudo pacman -S clamav",
                "update_cmd": "sudo pacman -Syu",
            },
            "ubuntu": {
                "pkg_manager": "apt",
                "install_cmd": "sudo apt install clamav clamav-freshclam clamav-daemon",
                "update_cmd": "sudo apt upgrade",
            },
            "debian": {
                "pkg_manager": "apt",
                "install_cmd": "sudo apt install clamav clamav-freshclam clamav-daemon",
                "update_cmd": "sudo apt upgrade",
            },
            "linuxmint": {
                "pkg_manager": "apt",
                "install_cmd": "sudo apt install clamav clamav-freshclam clamav-daemon",
                "update_cmd": "sudo apt upgrade",
            },
            "pop": {
                "pkg_manager": "apt",
                "install_cmd": "sudo apt install clamav clamav-freshclam clamav-daemon",
                "update_cmd": "sudo apt upgrade",
            },
            "fedora": {
                "pkg_manager": "dnf",
                "install_cmd": "sudo dnf install clamav clamav-update clamd",
                "update_cmd": "sudo dnf upgrade",
            },
            "rhel": {
                "pkg_manager": "dnf",
                "install_cmd": "sudo dnf install clamav clamav-update clamd",
                "update_cmd": "sudo dnf upgrade",
            },
            "centos": {
                "pkg_manager": "dnf",
                "install_cmd": "sudo dnf install clamav clamav-update clamd",
                "update_cmd": "sudo dnf upgrade",
            },
            "opensuse-tumbleweed": {
                "pkg_manager": "zypper",
                "install_cmd": "sudo zypper install clamav",
                "update_cmd": "sudo zypper update",
            },
            "opensuse-leap": {
                "pkg_manager": "zypper",
                "install_cmd": "sudo zypper install clamav",
                "update_cmd": "sudo zypper update",
            },
            "opensuse": {
                "pkg_manager": "zypper",
                "install_cmd": "sudo zypper install clamav",
                "update_cmd": "sudo zypper update",
            },
            "solus": {
                "pkg_manager": "eopkg",
                "install_cmd": "sudo eopkg install clamav",
                "update_cmd": "sudo eopkg upgrade",
            },
            "void": {
                "pkg_manager": "xbps",
                "install_cmd": "sudo xbps-install -S clamav",
                "update_cmd": "sudo xbps-install -Su",
            },
            "alpine": {
                "pkg_manager": "apk",
                "install_cmd": "sudo apk add clamav clamav-daemon",
                "update_cmd": "sudo apk upgrade",
            },
            "gentoo": {
                "pkg_manager": "emerge",
                "install_cmd": "sudo emerge --ask app-antivirus/clamav",
                "update_cmd": "sudo emerge --ask --update --deep @world",
            },
        }

        # Match by ID first, then by ID_LIKE
        info = pkg_map.get(distro_id)
        if info is None and id_like:
            for like_id in id_like.split():
                like_id = like_id.strip()
                info = pkg_map.get(like_id)
                if info:
                    break

        if info is not None:
            return {
                "id": distro_id,
                "name": name or distro_id.title(),
                "version": version,
                "pkg_manager": info["pkg_manager"],
                "install_cmd": info["install_cmd"],
                "update_cmd": info["update_cmd"],
                "unknown": "false",
            }

        # Unknown — generic fallback
        return {
            "id": distro_id or "unknown",
            "name": name or "Unknown Linux",
            "version": version,
            "pkg_manager": "",
            "install_cmd": "",
            "update_cmd": "",
            "unknown": "true",
        }

    @staticmethod
    def _read_os_release() -> dict[str, str]:
        """Parse /etc/os-release into a dict."""
        result: dict[str, str] = {}
        for path in ("/etc/os-release", "/usr/lib/os-release"):
            try:
                with open(path, encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "=" in line:
                            key, _, val = line.partition("=")
                            val = val.strip().strip('"').strip("'")
                            result[key.strip()] = val
                if "ID" in result:
                    return result
            except (OSError, IOError):
                continue
        return result
