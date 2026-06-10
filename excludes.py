"""Exclude pattern matching — cross-platform.

The actual set of common exclude patterns is provided by the platform
backend (backends/base.py → default_common_excludes).

This module contains only the matching & argument-building logic.
"""

import os
import re

from backends import backend


def get_common_excludes() -> dict[str, list[str]]:
    """Return the platform-appropriate common excludes from the backend."""
    return backend.default_common_excludes()


def get_active_exclude_patterns(
    enabled_common_excludes: set[str], user_excludes: list[str]
) -> list[str]:
    """Build a flat list of active exclude patterns from enabled common + user excludes."""
    common = get_common_excludes()
    patterns: list[str] = []

    for label in enabled_common_excludes:
        patterns.extend(common.get(label, []))

    for path in user_excludes:
        patterns.append(os.path.abspath(path))

    return patterns


def path_is_excluded(path: str, exclude_patterns: list[str]) -> bool:
    """Return True if *path* matches any pattern in *exclude_patterns*."""
    path_abs = os.path.abspath(path)
    normalized = path_abs.replace(os.sep, "/")

    for pattern in exclude_patterns:
        if os.path.isabs(pattern):
            # Absolute path prefix — case-insensitive on Windows
            pattern_abs = os.path.abspath(pattern)
            if os.name == "nt":
                if path_abs.lower().startswith(pattern_abs.lower()):
                    return True
            else:
                if path_abs.startswith(pattern_abs):
                    return True
        else:
            flags = re.IGNORECASE if os.name == "nt" else 0
            if re.search(pattern, normalized, flags):
                return True

    return False


def build_clamscan_exclude_args(exclude_patterns: list[str]) -> list[str]:
    """Convert exclude patterns into clamscan --exclude-dir CLI args."""
    args: list[str] = []

    for pattern in exclude_patterns:
        if os.path.isabs(pattern):
            normalized = os.path.abspath(pattern).replace(os.sep, "/")
            args.append(f"--exclude-dir=^{re.escape(normalized)}")
        else:
            args.append(f"--exclude-dir={pattern}")

    return args
