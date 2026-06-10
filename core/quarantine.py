"""Quarantine, delete, and restore operations for infected files.

Quarantine moves a detected file into an isolated directory, strips its
permissions, and records metadata so the file can be restored later
(e.g. in case of false positive).

Deletion is permanent and requires explicit confirmation in the UI layer.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from backends import backend


def list_quarantined_files() -> list[dict]:
    """Return metadata for quarantined files that still exist on disk."""
    qdir = backend.quarantine_dir()
    if not qdir.is_dir():
        return []

    items: list[dict] = []
    for meta_path in sorted(qdir.glob("*.json")):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        quarantine_name = meta.get("quarantine_name")
        if not isinstance(quarantine_name, str) or not quarantine_name:
            quarantine_name = meta_path.stem

        qpath = qdir / quarantine_name
        if not qpath.is_file():
            continue

        meta["quarantine_name"] = quarantine_name
        meta["quarantine_path"] = str(qpath)
        meta["metadata_path"] = str(meta_path)
        items.append(meta)

    return items


# ── quarantine ─────────────────────────────────────────────────────────

def quarantine_file(original_path: str, threat_name: str) -> str:
    """Move *original_path* into quarantine and return a status message.

    The file is renamed to a hash-based name, permissions are stripped
    (read-only on all platforms), and a metadata JSON is saved alongside.

    Returns a one-line status string suitable for UI display.
    """
    src = Path(original_path)

    if not src.exists():
        return f"File not found: {original_path}"

    if not src.is_file():
        return f"Not a regular file: {original_path}"

    qdir = backend.quarantine_dir()
    qdir.mkdir(parents=True, exist_ok=True)

    # Generate unique quarantine name
    ts = datetime.now(timezone.utc).isoformat()
    unique = hashlib.sha256(f"{original_path}{ts}".encode()).hexdigest()[:12]
    safe_suffix = _safe_name(src.name)
    qname = f"{unique}_{safe_suffix}"
    dest = qdir / qname

    try:
        shutil.move(str(src), str(dest))
    except (OSError, PermissionError) as exc:
        return f"Cannot quarantine: {exc}"

    # Strip permissions — make non-executable, read-only
    try:
        _strip_permissions(dest)
    except OSError:
        pass  # best-effort

    # Write metadata
    meta = {
        "schema_version": 1,
        "original_path": str(src.resolve()),
        "threat_name": threat_name,
        "quarantined_at": ts,
        "original_size": _file_size(dest),
        "quarantine_name": qname,
    }

    meta_path = qdir / f"{unique}_{safe_suffix}.json"
    try:
        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    except OSError:
        pass  # file is already moved, this is non-critical

    return f"Quarantined: {original_path}"


# ── delete ─────────────────────────────────────────────────────────────

def delete_file(original_path: str) -> str:
    """Permanently delete *original_path* and return a status message."""
    src = Path(original_path)

    if not src.exists():
        return f"File not found: {original_path}"

    if not src.is_file():
        return f"Not a regular file: {original_path}"

    try:
        src.unlink()
        return f"Deleted: {original_path}"
    except (OSError, PermissionError) as exc:
        return f"Cannot delete: {exc}"


# ── restore (undo quarantine) ──────────────────────────────────────────

def restore_file(quarantine_name: str, *, overwrite: bool = False) -> str:
    """Restore a quarantined file to its original location.

    *quarantine_name* is the name of the quarantined file (not the .json).
    """
    qdir = backend.quarantine_dir()
    qpath = qdir / quarantine_name

    if not qpath.exists():
        return f"Quarantined file not found: {quarantine_name}"

    # Find metadata
    meta_path = _find_meta_for(qdir, quarantine_name)
    if meta_path is None:
        return f"No metadata found for: {quarantine_name}"

    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return f"Corrupt metadata for: {quarantine_name}"

    original = Path(meta.get("original_path", ""))
    if not original.parent.exists():
        return f"Original location no longer exists: {original}"
    if original.exists() and not overwrite:
        return f"Original file already exists: {original}"
    if original.exists() and overwrite and not original.is_file():
        return f"Cannot overwrite non-file path: {original}"

    try:
        if original.exists() and overwrite:
            original.unlink()
        shutil.move(str(qpath), str(original))
        os.chmod(original, stat.S_IRUSR | stat.S_IWUSR)  # restore write perm
        meta_path.unlink(missing_ok=True)
        return f"Restored: {original}"
    except (OSError, PermissionError) as exc:
        return f"Cannot restore: {exc}"


def delete_quarantined_file(quarantine_name: str) -> str:
    """Permanently delete a quarantined file and its metadata."""
    qdir = backend.quarantine_dir()
    qpath = qdir / quarantine_name

    if not qpath.exists():
        return f"Quarantined file not found: {quarantine_name}"

    if not qpath.is_file():
        return f"Not a regular quarantined file: {quarantine_name}"

    meta_path = _find_meta_for(qdir, quarantine_name)

    try:
        qpath.unlink()
        if meta_path is not None:
            meta_path.unlink(missing_ok=True)
        return f"Permanently deleted: {quarantine_name}"
    except (OSError, PermissionError) as exc:
        return f"Cannot delete quarantined file: {exc}"


# ── open location ──────────────────────────────────────────────────────

def open_file_location(file_path: str) -> str:
    """Open the parent directory of *file_path* in the system file manager.

    Returns a status string or empty string on success.
    """
    parent = os.path.dirname(os.path.abspath(file_path))
    if not os.path.isdir(parent):
        return f"Directory not found: {parent}"

    try:
        if sys.platform == "win32":
            # Open Explorer with the file selected
            subprocess.Popen(
                ["explorer", "/select,", os.path.abspath(file_path)],
                creationflags=subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW")
                else 0,
            )
        elif sys.platform == "darwin":
            subprocess.Popen(["open", "-R", os.path.abspath(file_path)])
        else:
            # Linux — xdg-open the parent directory
            subprocess.Popen(["xdg-open", parent])
    except Exception as exc:
        return f"Cannot open location: {exc}"

    return ""


# ── helpers ────────────────────────────────────────────────────────────

def _safe_name(filename: str) -> str:
    """Replace path-separator-like characters in a filename."""
    return filename.replace("/", "_").replace("\\", "_")


def _strip_permissions(path: Path) -> None:
    """Strip all permissions except owner-read (0o400)."""
    os.chmod(path, stat.S_IRUSR)


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _find_meta_for(qdir: Path, quarantine_name: str) -> Path | None:
    """Find the .json metadata file for a quarantined file."""
    meta_path = qdir / (quarantine_name + ".json")
    if meta_path.exists():
        return meta_path

    # Fallback: scan for .json files with matching prefix
    prefix = quarantine_name.split("_")[0] if "_" in quarantine_name else ""
    if prefix:
        for candidate in sorted(qdir.glob(f"{prefix}_*.json")):
            return candidate

    return None
