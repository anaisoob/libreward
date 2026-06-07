import os
import re


COMMON_EXCLUDES = {
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
        os.path.join(os.path.expanduser("~"), ".local/share/containers/storage"),
    ],
}


def get_active_exclude_patterns(enabled_common_excludes, user_excludes):
    """Build a flat list of active exclude patterns from enabled common + user excludes."""
    patterns = []

    for label in enabled_common_excludes:
        patterns.extend(COMMON_EXCLUDES.get(label, []))

    for path in user_excludes:
        patterns.append(os.path.abspath(path))

    return patterns


def path_is_excluded(path, exclude_patterns):
    """Return True if *path* matches any pattern in *exclude_patterns*."""
    path_abs = os.path.abspath(path)
    normalized = path_abs.replace(os.sep, "/")

    for pattern in exclude_patterns:
        if pattern.startswith("/"):
            if path_abs.startswith(pattern):
                return True
        else:
            if re.search(pattern, normalized):
                return True

    return False


def build_clamscan_exclude_args(exclude_patterns):
    """Convert exclude patterns into clamscan --exclude-dir CLI args."""
    args = []

    for pattern in exclude_patterns:
        if pattern.startswith("/"):
            args.append(f"--exclude-dir=^{re.escape(pattern)}")
        else:
            args.append(f"--exclude-dir={pattern}")

    return args
