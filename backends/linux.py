import os
import signal
import shutil
import subprocess

from .base import PlatformBackend


class LinuxBackend(PlatformBackend):
    """Platform backend for Linux."""

    def start_process(self, cmd, **kwargs):
        """Start a subprocess in its own process group (os.setsid)."""
        kwargs.setdefault("preexec_fn", os.setsid)
        return subprocess.Popen(cmd, **kwargs)

    def stop_process(self, process):
        """Terminate an entire process group via SIGTERM."""
        if process.poll() is None:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)

    def find_clamscan(self) -> str | None:
        return shutil.which("clamscan")

    def find_freshclam(self) -> str | None:
        return shutil.which("freshclam")

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
