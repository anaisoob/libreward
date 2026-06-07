"""Platform backends — auto-selects Linux or Windows at import time.

Usage:
    from backends import backend

    process = backend.start_process(cmd, stdout=PIPE, ...)
    backend.stop_process(process)
    path = backend.find_clamscan()
"""

import sys

if sys.platform == "win32":
    from .windows import WindowsBackend as _Backend
else:
    from .linux import LinuxBackend as _Backend

backend = _Backend()
