"""Quarantine, delete, and restore operations for infected files.

Quarantine moves a detected file into an isolated directory in an encoded,
unusable form (a header and XOR with a fixed key), strips its permissions,
and records metadata so the file can be restored later (e.g. in case of a
false positive). A copy taken out of quarantine by hand cannot be run or
opened, and other scanners and file indexers do not see the harmful content.
The encoding neutralises the file; it is not secret, LibreWard is open source.

Deletion is permanent and requires explicit confirmation in the UI layer.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath

from backends import backend
from backends.linux_root_quarantine import HEADER, xor as _xor  # noqa: F401 - one format

# Files from older versions without the header are stored as they were and
# restored as they are.
CHUNK = 1024 * 1024


def list_quarantined_files() -> list[dict]:
    """Return metadata for quarantined files that still exist on disk."""
    qdir = backend.quarantine_dir()
    if not qdir.is_dir():
        return []

    items: list[dict] = []
    for meta_path in sorted(qdir.glob("*.json")):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, UnicodeError):
            continue

        if not isinstance(meta, dict) or meta_path.is_symlink():
            continue
        quarantine_name = meta.get("quarantine_name")
        if not isinstance(quarantine_name, str) or not quarantine_name:
            quarantine_name = meta_path.stem

        qpath = _quarantine_path(qdir, quarantine_name)
        if meta_path.name != quarantine_name + ".json":
            continue
        # A file in the system quarantine has only this note here.
        if qpath is None or not (qpath.is_file() or meta.get("system") is True):
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

    if src.is_symlink() or not src.is_file():
        return f"Not a regular file: {original_path}"

    qdir = backend.quarantine_dir()
    qdir.mkdir(parents=True, exist_ok=True)

    # Generate unique quarantine name
    ts = datetime.now(timezone.utc).isoformat()
    unique = hashlib.sha256(f"{original_path}{ts}".encode()).hexdigest()[:12]
    safe_suffix = _safe_name(src.name)
    qname = f"{unique}_{safe_suffix}"
    dest = qdir / qname

    # Persist restore information before moving anything. If metadata cannot
    # be saved, leave the original file untouched.
    meta_path = qdir / (qname + ".json")
    try:
        meta = {
            "schema_version": 1,
            "original_path": str(src.absolute()),
            "original_mode": stat.S_IMODE(src.stat().st_mode),
            "threat_name": threat_name,
            "quarantined_at": ts,
            "original_size": src.stat().st_size,
            "quarantine_name": qname,
        }
        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    except OSError as exc:
        meta_path.unlink(missing_ok=True)
        return f"Cannot quarantine: cannot save restore metadata: {exc}"

    # The encoded copy is complete before the original goes away; any failure
    # leaves the original where it was and nothing in quarantine.
    try:
        meta["sha256"], copied = _encode_into(src, dest)
        meta["encoded"] = True
        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        _remove_if_unchanged(src, copied)
    except OSError as exc:
        dest.unlink(missing_ok=True)
        meta_path.unlink(missing_ok=True)
        return f"Cannot quarantine: {exc}"

    try:
        _strip_permissions(dest)
    except OSError:
        pass  # best-effort; metadata still allows restoration

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
    qpath = _quarantine_path(qdir, quarantine_name)
    if qpath is None:
        return "Invalid quarantine name or path"

    if not qpath.exists():
        return f"Quarantined file not found: {quarantine_name}"

    # Find metadata
    meta_path = _find_meta_for(qdir, quarantine_name)
    if meta_path is None:
        return f"No metadata found for: {quarantine_name}"

    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeError):
        return f"Corrupt metadata for: {quarantine_name}"

    if not isinstance(meta, dict) or not isinstance(meta.get("original_path"), str):
        return f"Corrupt metadata for: {quarantine_name}"
    original = Path(meta["original_path"])
    if not original.is_absolute():
        return f"Invalid original location: {original}"
    mode = meta.get("original_mode", stat.S_IRUSR | stat.S_IWUSR)
    if not isinstance(mode, int) or not 0 <= mode <= 0o7777:
        return f"Corrupt metadata for: {quarantine_name}"
    if not original.parent.exists():
        return f"Original location no longer exists: {original}"
    if original.exists() and not overwrite:
        return f"Original file already exists: {original}"
    if original.exists() and overwrite and not original.is_file():
        return f"Cannot overwrite non-file path: {original}"

    # A new file of our own next to the original location: complete and checked
    # before it takes the original name. The quarantined copy stays until then.
    try:
        descriptor, name = tempfile.mkstemp(prefix=".libreward-restore-", dir=original.parent)
    except OSError as exc:
        return f"Cannot restore: {exc}"
    temporary = Path(name)
    try:
        digest = _decode_into(qpath, descriptor, _is_encoded(qpath))
        expected = meta.get("sha256")
        if isinstance(expected, str) and digest != expected:
            return f"Cannot restore: the quarantined copy of {original.name} is damaged"
        os.chmod(temporary, mode & 0o777)  # do not restore special privilege bits
        if overwrite:
            os.replace(temporary, original)
        else:
            _place_new(temporary, original)
        os.chmod(qpath, stat.S_IRUSR | stat.S_IWUSR)
        qpath.unlink()
        meta_path.unlink(missing_ok=True)
        return f"Restored: {original}"
    except FileExistsError:
        return f"Original file already exists: {original}"
    except OSError as exc:
        return f"Cannot restore: {exc}"
    finally:
        temporary.unlink(missing_ok=True)


def delete_quarantined_file(quarantine_name: str) -> str:
    """Permanently delete a quarantined file and its metadata."""
    qdir = backend.quarantine_dir()
    qpath = _quarantine_path(qdir, quarantine_name)
    if qpath is None:
        return "Invalid quarantine name or path"

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


def _open_regular(path: Path):
    """Open for reading without following a symlink swapped in after the checks."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    return os.fdopen(os.open(path, flags), "rb")


def _identity(status: os.stat_result) -> tuple:
    """Which file this is and whether its contents were changed."""
    return status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns


def _encode_into(src: Path, dest: Path) -> tuple[str, tuple]:
    """Write the encoded copy of `src` to `dest`.

    Returns the SHA256 of the original and the identity of the file copied.
    """
    digest = hashlib.sha256()
    offset = 0
    with _open_regular(src) as source, open(dest, "xb") as target:
        copied = _identity(os.fstat(source.fileno()))
        target.write(HEADER)
        while chunk := source.read(CHUNK):
            digest.update(chunk)
            target.write(_xor(chunk, offset))
            offset += len(chunk)
        target.flush()
        os.fsync(target.fileno())
        if _identity(os.fstat(source.fileno())) != copied:
            raise OSError("the file changed while it was being copied")
    return digest.hexdigest(), copied


def _remove_if_unchanged(src: Path, copied: tuple) -> None:
    """Remove `src` only if it is still the file that was copied.

    Renaming first takes that one file off the path, so a file that appears
    there afterwards is never touched. Anything else goes back where it was.
    """
    held = src.with_name(f".libreward-quarantine-{secrets.token_hex(8)}")
    os.rename(src, held)
    try:
        if _identity(os.lstat(held)) != copied:
            raise OSError("the file changed while it was being copied")
        held.unlink()
    except OSError as exc:
        try:
            _place_new(held, src)
        except FileExistsError:
            raise OSError(f"{exc}; a new file took its place, it was kept as {held}") from exc
        raise


def _place_new(source: Path, target: Path) -> None:
    """Move `source` to `target`; FileExistsError if that name is already taken.

    Checking first would leave a gap, and a rename on Linux replaces what it finds.
    """
    if os.name == "nt":
        os.rename(source, target)  # refuses an existing name on Windows
        return
    try:
        os.link(source, target, follow_symlinks=False)
    except FileExistsError:
        raise
    except OSError:  # no hard links here, for example on a FAT USB stick
        with open(source, "rb") as stream, open(target, "xb") as copy:
            try:
                shutil.copyfileobj(stream, copy)
                shutil.copymode(source, target)
            except OSError:
                target.unlink(missing_ok=True)
                raise
    source.unlink()


def _is_encoded(path: Path) -> bool:
    try:
        with open(path, "rb") as stream:
            return stream.read(len(HEADER)) == HEADER
    except OSError:
        return False


def _decode_into(qpath: Path, descriptor: int, encoded: bool) -> str:
    """Write the original contents to the open file `descriptor`; returns their SHA256."""
    digest = hashlib.sha256()
    offset = 0
    with open(qpath, "rb") as source, os.fdopen(descriptor, "wb") as target:
        if encoded:
            source.read(len(HEADER))
        while chunk := source.read(CHUNK):
            data = _xor(chunk, offset) if encoded else chunk
            digest.update(data)
            target.write(data)
            offset += len(chunk)
        target.flush()
        os.fsync(target.fileno())
    return digest.hexdigest()


def _strip_permissions(path: Path) -> None:
    """Strip all permissions except owner-read (0o400)."""
    os.chmod(path, stat.S_IRUSR)


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _quarantine_path(qdir: Path, name: str) -> Path | None:
    """Accept a direct child only; never follow symlinks outside quarantine."""
    if (not isinstance(name, str) or not name or name in (".", "..")
            or "/" in name or "\\" in name or PureWindowsPath(name).drive):
        return None
    path = qdir / name
    if path.is_symlink() or path.resolve().parent != qdir.resolve():
        return None
    return path


def _find_meta_for(qdir: Path, quarantine_name: str) -> Path | None:
    """Match only the exact metadata file for this quarantined item."""
    meta_path = _quarantine_path(qdir, quarantine_name + ".json")
    return meta_path if meta_path is not None and meta_path.is_file() else None
