"""ClamAV runtime updater.

Full update flow for Windows (and potentially Linux in the future):

    1. Fetch update manifest (from Codeberg, with local fallback)
    2. Check minimal_libreward_version
    3. Compare local ClamAV version with latest in manifest
    4. If update available → ask user
    5. Download official ClamAV portable ZIP
    6. Verify SHA256
    7. Extract into staging directory
    8. Normalize extracted layout (flatten extract_dir contents)
    9. Validate new runtime (run clamscan.exe --version, freshclam.exe --version)
    10. Move current/ → previous/, staging → current/
    11. Update config.json
    12. Cleanup

The update lock (.runtime-update.lock) prevents concurrent updates.
"""

import hashlib
import json
import os
import shutil
import subprocess
import urllib.request
import zipfile
from pathlib import Path, PureWindowsPath
from typing import Callable

from backends import backend
from core.constants import (
    APP_VERSION,
    CLAMAV_RUNTIME_MANIFEST_URL,
)
from core.runtime import (
    is_update_locked,
    create_update_lock,
    release_update_lock,
    is_newer_version,
)

# Local manifest shipped with the app — used as a fallback if the network
# fetch fails, and as a reference for local-only offline mode.
_LOCAL_MANIFEST_PATH = Path(__file__).resolve().parent.parent / "updates" / "clamav-runtime-windows.json"


# ── manifest handling ───────────────────────────────────────────────

def _load_local_manifest() -> dict | None:
    """Load the bundled local manifest file. Returns None on failure."""
    try:
        return json.loads(_LOCAL_MANIFEST_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None


def fetch_manifest(timeout: int = 15) -> dict:
    """Fetch the update manifest.

    Tries the Codeberg URL first, falls back to the local bundled manifest.
    Raises RuntimeError if both fail.
    """
    errors: list[str] = []

    # 1 — try remote
    try:
        request = urllib.request.Request(
            CLAMAV_RUNTIME_MANIFEST_URL,
            headers={"User-Agent": f"LibreWard-Updater/{APP_VERSION}"},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status == 200:
                data = response.read().decode("utf-8")
                return json.loads(data)
            else:
                errors.append(f"HTTP {response.status}")
    except Exception as e:
        errors.append(str(e))

    # 2 — fall back to local
    local = _load_local_manifest()
    if local:
        return local

    raise RuntimeError(
        f"Could not fetch update manifest: {'; '.join(errors)}"
    )


def get_platform_entry(manifest: dict) -> dict | None:
    """Extract the platform entry matching the current OS and architecture.

    Returns the platform dict from the manifest, or None if not found.
    """
    pa = backend.platform_arch()
    platforms = manifest.get("platforms", {})
    return platforms.get(pa)


# ── update check ────────────────────────────────────────────────────

def check_for_updates(log: Callable[[str], None] | None = None) -> dict | None:
    """Check if a ClamAV runtime update is available.

    Only works on platforms that manage their own runtime (Windows).
    On Linux, ClamAV updates are handled by the system package manager.

    Returns the platform entry dict if an update is available,
    or None if current is up-to-date / no update needed.
    Raises RuntimeError if the manifest cannot be fetched.
    """
    if not backend.manages_own_runtime():
        if log:
            log("ClamAV updates are handled by your system's package manager.\n")
        return None
    manifest = fetch_manifest()
    platform_entry = get_platform_entry(manifest)
    if platform_entry is None:
        if log:
            log(f"No manifest entry for platform: {backend.platform_arch()}\n")
        return None

    # Check minimal LibreWard version.
    min_ver = platform_entry.get("minimal_libreward_version", "0")
    if min_ver and _version_tuple(min_ver) > _version_tuple(APP_VERSION):
        if log:
            log(
                f"Update requires LibreWard >= {min_ver}, "
                f"but running {APP_VERSION}. Skipping.\n"
            )
        return None

    latest_ver = platform_entry.get("latest_version")

    # Get current local version
    runtime = backend.detect_clamav_runtime()
    current_ver = runtime.version_num

    if log:
        log(f"Current ClamAV: {current_ver or 'unknown'}\n")
        log(f"Latest ClamAV:  {latest_ver}\n")

    if current_ver and latest_ver and not is_newer_version(latest_ver, current_ver):
        if log:
            log("ClamAV runtime is up to date.\n")
        return None

    if log:
        log("Update available.\n")

    return platform_entry


# ── download ────────────────────────────────────────────────────────

def _download_file(url: str, dest: Path, progress_callback=None, timeout: int = 600) -> None:
    """Download a file from *url* to *dest*.

    *progress_callback* receives (bytes_downloaded, bytes_total) periodically.
    """
    request = urllib.request.Request(
        url,
        headers={"User-Agent": f"LibreWard-Updater/{APP_VERSION}"},
    )

    with urllib.request.urlopen(request, timeout=timeout) as response:
        content_length = response.headers.get("Content-Length")
        total = int(content_length) if content_length else None

        downloaded = 0
        chunk_size = 65536  # 64 KB

        with open(dest, "wb") as f:
            while True:
                chunk = response.read(chunk_size)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                if progress_callback and total:
                    progress_callback(downloaded, total)


def _verify_sha256(file_path: Path, expected_sha256: str) -> bool:
    """Verify SHA256 of a file. Returns True on match."""
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            sha.update(chunk)
    return sha.hexdigest() == expected_sha256.lower()


# ── extraction & normalization ──────────────────────────────────────

def _extract_zip(zip_path: Path, dest_dir: Path) -> None:
    """Extract a ZIP file into *dest_dir* after path traversal validation."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        _validate_zip_members(zf, dest_dir)
        zf.extractall(dest_dir)


def _validate_zip_members(zf: zipfile.ZipFile, dest_dir: Path) -> None:
    """Reject ZIP entries that would extract outside *dest_dir*."""
    dest_root = dest_dir.resolve()

    for member in zf.infolist():
        name = member.filename
        windows_path = PureWindowsPath(name)
        if windows_path.drive or windows_path.is_absolute():
            raise RuntimeError(f"Unsafe ZIP entry path: {name!r}")

        target = (dest_root / name).resolve()
        try:
            common = os.path.commonpath([str(dest_root), str(target)])
        except ValueError:
            raise RuntimeError(f"Unsafe ZIP entry path: {name!r}")

        if common != str(dest_root):
            raise RuntimeError(f"Unsafe ZIP entry path: {name!r}")


def _normalize_runtime(source_dir: Path, target_dir: Path, extract_subdir: str) -> None:
    """Normalize the extracted runtime layout.

    The official ClamAV ZIP extracts into an inner folder like:
        staging/clamav-1.5.2.win.x64/clamscan.exe, freshclam.exe, ...

    We flatten this by moving the *contents* of that inner folder
    into *target_dir* so the final layout is:
        target_dir/clamscan.exe, freshclam.exe, ...

    If *extract_subdir* is empty, the source_dir contents are moved directly.
    """
    if extract_subdir:
        inner = source_dir / extract_subdir
        if not inner.is_dir():
            raise RuntimeError(
                f"Expected extract_dir '{extract_subdir}' not found in ZIP. "
                f"Contents: {sorted(p.name for p in source_dir.iterdir())}"
            )
    else:
        inner = source_dir

    target_dir.mkdir(parents=True, exist_ok=True)

    for item in inner.iterdir():
        dest = target_dir / item.name
        if dest.exists():
            if dest.is_dir():
                shutil.rmtree(dest)
            else:
                dest.unlink()
        shutil.move(str(item), str(dest))


# ── runtime validation ──────────────────────────────────────────────

def _validate_runtime(runtime_dir: Path, validation_commands: list[str]) -> None:
    """Run validation commands on an extracted runtime.

    Raises RuntimeError if any command fails.
    Each command is run from *runtime_dir* with just the executable name
    (e.g. "clamscan.exe --version").
    """
    for cmd_str in validation_commands:
        parts = cmd_str.split()
        exe_name = parts[0]
        exe_args = parts[1:]
        exe_path = runtime_dir / exe_name

        if not exe_path.is_file():
            raise RuntimeError(
                f"Validation failed: {exe_name} not found in extracted runtime"
            )

        try:
            result = subprocess.run(
                [str(exe_path)] + exe_args,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(runtime_dir),
                # On Windows, suppress console windows during validation
                **(
                    {"creationflags": subprocess.CREATE_NO_WINDOW}
                    if os.name == "nt"
                    else {}
                ),
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"Validation failed: {cmd_str!r} returned {result.returncode}\n"
                    f"stderr: {result.stderr.strip()}"
                )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Validation timed out: {cmd_str!r}")
        except FileNotFoundError:
            raise RuntimeError(f"Validation failed: {exe_name} not found")


def _install_runtime_with_rollback(new_runtime_dir: Path) -> None:
    """Install *new_runtime_dir* as current/, restoring old current/ on failure."""
    runtime_parent = backend.data_dir() / "clamav-runtime"
    current_dir = runtime_parent / "current"
    previous_dir = runtime_parent / "previous"
    installing_dir = runtime_parent / "current.installing"

    runtime_parent.mkdir(parents=True, exist_ok=True)

    if installing_dir.exists():
        shutil.rmtree(installing_dir)

    shutil.move(str(new_runtime_dir), str(installing_dir))

    try:
        if previous_dir.exists():
            shutil.rmtree(previous_dir)

        if current_dir.exists():
            shutil.move(str(current_dir), str(previous_dir))

        shutil.move(str(installing_dir), str(current_dir))

    except Exception:
        if not current_dir.exists() and previous_dir.exists():
            shutil.move(str(previous_dir), str(current_dir))
        if installing_dir.exists():
            shutil.rmtree(installing_dir)
        raise


def cleanup_stale_update_artifacts() -> None:
    """Remove leftover update staging directories from interrupted updates."""
    updates_dir = backend.updates_dir()
    runtime_parent = backend.data_dir() / "clamav-runtime"

    for path in (
        updates_dir / "clamav-staging",
        updates_dir / "clamav-normalized",
        runtime_parent / "current.installing",
    ):
        try:
            if path.exists():
                shutil.rmtree(path)
        except OSError:
            pass


# ── main update flow ────────────────────────────────────────────────

def perform_update(
    platform_entry: dict,
    log: Callable[[str], None] | None = None,
    progress: Callable[[str, int, int | None], None] | None = None,
) -> RuntimeError | None:
    """Execute the full ClamAV runtime update.

    Args:
        platform_entry: The platform dict from the update manifest.
        log: Called with status message strings.
        progress: Called with (phase_name, current_bytes, total_bytes_or_None).

    Returns:
        RuntimeError on failure, None on success.

    Only works on platforms that manage their own runtime (Windows).
    On Linux, returns a RuntimeError immediately.
    """
    if not backend.manages_own_runtime():
        return RuntimeError(
            "Automatic ClamAV runtime updates are not supported on this platform.\n"
            "ClamAV updates are handled by your system's package manager."
        )
    download_info = platform_entry.get("download", {})
    url = download_info.get("url")
    expected_sha256 = download_info.get("sha256", "").lower()
    extract_dir = download_info.get("extract_dir", "")
    runtime_root_mode = download_info.get("runtime_root_mode", "contents-of-extract-dir")
    validation = platform_entry.get("validation", {})
    validation_commands = validation.get("commands", [])

    if not url:
        return RuntimeError("Manifest missing download URL.")

    # ── lock ────────────────────────────────────────────────────
    if is_update_locked():
        return RuntimeError("An update is already in progress (lock file exists).")

    create_update_lock()

    updates_dir = backend.updates_dir()
    staging_dir = updates_dir / "clamav-staging"
    zip_dest = updates_dir / "clamav-runtime.zip"

    try:
        cleanup_stale_update_artifacts()

        # ── download ────────────────────────────────────────────
        if log:
            log("Downloading ClamAV runtime...\n")

        updates_dir.mkdir(parents=True, exist_ok=True)

        def _progress(done, total):
            if progress:
                progress("download", done, total)

        _download_file(url, zip_dest, progress_callback=_progress)

        if log:
            log(f"Downloaded to: {zip_dest}\n")
            log(f"File size: {zip_dest.stat().st_size:,} bytes\n")

        # ── verify SHA256 ────────────────────────────────────────
        if log:
            log("Verifying SHA256 checksum...\n")

        if not _verify_sha256(zip_dest, expected_sha256):
            return RuntimeError(
                f"SHA256 verification failed.\n"
                f"Expected: {expected_sha256}\n"
                f"The downloaded file may be corrupted or tampered with."
            )

        if log:
            log("SHA256 checksum OK.\n")

        # ── extract ──────────────────────────────────────────────
        if log:
            log(f"Extracting to: {staging_dir}\n")

        # Clean staging first
        if staging_dir.exists():
            shutil.rmtree(staging_dir)

        _extract_zip(zip_dest, staging_dir)

        if log:
            log(
                f"Extracted: {sorted(p.name for p in staging_dir.iterdir())}\n"
            )

        # ── normalize ────────────────────────────────────────────
        if runtime_root_mode == "contents-of-extract-dir":
            normalized_dir = updates_dir / "clamav-normalized"
            if normalized_dir.exists():
                shutil.rmtree(normalized_dir)

            if log:
                log(f"Normalizing runtime layout (extract_dir: {extract_dir})...\n")

            _normalize_runtime(staging_dir, normalized_dir, extract_dir)
            new_runtime_dir = normalized_dir
        else:
            new_runtime_dir = staging_dir

        if log:
            log(
                f"New runtime contents: "
                f"{sorted(p.name for p in new_runtime_dir.iterdir())}\n"
            )

        # ── validate ─────────────────────────────────────────────
        if log:
            log("Validating new runtime...\n")

        _validate_runtime(new_runtime_dir, validation_commands)

        if log:
            log("Validation OK.\n")

        # ── switch runtimes ──────────────────────────────────────
        if log:
            log("Installing new runtime...\n")

        _install_runtime_with_rollback(new_runtime_dir)

        if log:
            log("Runtime installed successfully.\n")

        # ── cleanup ──────────────────────────────────────────────
        if zip_dest.exists():
            zip_dest.unlink()
        if staging_dir.exists():
            shutil.rmtree(staging_dir)
        # normalized_dir was moved, but clean up if still present
        if (updates_dir / "clamav-normalized").exists():
            shutil.rmtree(updates_dir / "clamav-normalized")

        return None  # success

    except Exception as e:
        return RuntimeError(f"Update failed: {e}")

    finally:
        release_update_lock()


# ── helpers ─────────────────────────────────────────────────────────

def _version_tuple(ver: str | None) -> tuple[int, ...]:
    if not ver:
        return (0,)
    try:
        return tuple(int(x) for x in ver.split("."))
    except (ValueError, TypeError):
        return (0,)
