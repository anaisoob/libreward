import shutil
import subprocess

from .base import PlatformBackend


class WindowsBackend(PlatformBackend):
    """Platform backend for Windows."""

    def start_process(self, cmd, **kwargs):
        """Start a subprocess with CREATE_NEW_PROCESS_GROUP so it can be
        terminated as a unit."""
        flags = kwargs.pop("creationflags", 0)
        flags |= subprocess.CREATE_NEW_PROCESS_GROUP
        return subprocess.Popen(cmd, creationflags=flags, **kwargs)

    def stop_process(self, process):
        """Terminate a process via its terminate() method."""
        if process.poll() is None:
            process.terminate()

    def find_clamscan(self) -> str | None:
        return shutil.which("clamscan")

    def find_freshclam(self) -> str | None:
        return shutil.which("freshclam")

    def default_common_excludes(self) -> dict[str, list[str]]:
        return {
            "Python virtual environments (.venv, venv, env)": [
                r"(^|\\)\.venv($|\\)",
                r"(^|\\)venv($|\\)",
                r"(^|\\)env($|\\)",
            ],
            "Python cache dirs (__pycache__, .pytest_cache, .mypy_cache, .ruff_cache)": [
                r"(^|\\)__pycache__($|\\)",
                r"(^|\\)\.pytest_cache($|\\)",
                r"(^|\\)\.mypy_cache($|\\)",
                r"(^|\\)\.ruff_cache($|\\)",
            ],
            "Node.js dependencies (node_modules)": [
                r"(^|\\)node_modules($|\\)",
            ],
            "Git directories (.git)": [
                r"(^|\\)\.git($|\\)",
            ],
            "Windows recycle bin": [
                r"(^|\\)\$RECYCLE\.BIN($|\\)",
            ],
            "System Volume Information": [
                r"(^|\\)System Volume Information($|\\)",
            ],
        }
