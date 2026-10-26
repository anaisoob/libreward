"""What a Quick scan checks: where threats arrive and what starts by itself."""
import os
from pathlib import Path

from backends import backend
from core.download_folders import discover_download_folders


def quick_scan_targets():
    """Existing folders and files for a Quick scan, without duplicates.

    The platform's places, the folders browsers download to, and the programs
    that start at login wherever they are stored.
    """
    targets = list(backend.quick_scan_paths())
    home = os.path.normcase(os.path.realpath(Path.home()))
    try:
        for folder in discover_download_folders():
            # A browser saving to the home folder would turn this into a full scan.
            path = os.path.normcase(folder.path).rstrip(os.sep)
            if home != path and not home.startswith(path + os.sep):
                targets.append(folder.path)
    except OSError:
        pass
    targets += backend.autostart_programs()
    return list(dict.fromkeys(path for path in targets if os.path.exists(path)))


def quick_scan_excludes():
    return backend.quick_scan_excludes()
