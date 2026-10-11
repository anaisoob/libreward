"""Exclude pattern matching — cross-platform.

The actual set of common exclude patterns is provided by the platform
backend (backends/base.py → default_common_excludes).

This module contains only the matching & argument-building logic.
"""

import os
import re

from backends import backend


def mandatory_exclude_patterns():
    """Quarantined files must not be rediscovered as active threats."""
    return [os.path.abspath(backend.quarantine_dir())]


def get_common_excludes() -> dict[str, list[str]]:
    """Return the platform-appropriate common excludes from the backend."""
    return backend.default_common_excludes()


def get_active_exclude_patterns(
    enabled_common_excludes: set[str], user_excludes: list[str]
) -> list[str]:
    """Build a flat list of active exclude patterns from enabled common + user excludes."""
    common = get_common_excludes()
    patterns: list[str] = mandatory_exclude_patterns()

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
            # Match the path itself or a child, never a similarly named sibling.
            candidate = os.path.normcase(path_abs)
            excluded = os.path.normcase(os.path.abspath(pattern))
            if candidate == excluded or candidate.startswith(excluded.rstrip(os.sep) + os.sep):
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
            # ClamAV uses POSIX ERE, not Python/PCRE. Inline flags and
            # non-capturing groups are unsupported. ClamAV itself enables
            # REG_ICASE on Windows; match both native and normalized separators.
            escaped = _clamav_literal(normalized)
            if os.path.isfile(pattern):
                args.append(f"--exclude=^{escaped}$")
            else:
                escaped = _clamav_literal(normalized.rstrip("/"))
                separator = r"[/\\]" if os.name == "nt" else "/"
                args.append(f"--exclude-dir=^{escaped}({separator}|$)")
        else:
            if os.name == "nt":
                pattern = pattern.replace("/", r"[/\\]")
            args.append(f"--exclude-dir={pattern}")

    return args


def _clamav_literal(path: str) -> str:
    """Escape literal paths using only POSIX extended regex syntax."""
    escaped = "".join("\\" + char if char in r".\^$*+?{}[]()|" else char for char in path)
    return escaped.replace("/", r"[/\\]") if os.name == "nt" else escaped
