"""Platform backends — auto-selects Linux or Windows at import time.

Usage:
    from backends import backend, RuntimeInfo

    runtime = backend.detect_clamav_runtime()
    process = backend.start_process(cmd, stdout=PIPE, ...)
    backend.stop_process(process)
"""

import sys

if sys.platform == "win32":
    from .windows import WindowsBackend as _Backend
else:
    from .linux import LinuxBackend as _Backend

from .base import RuntimeInfo  # noqa: E402, F401 — re-export

backend = _Backend()
