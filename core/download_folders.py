"""Read local download preferences; never launch browsers or execute config code."""
import configparser
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re

from backends import backend

MAX_SETTINGS_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class DownloadFolder:
    path: str
    sources: tuple[str, ...]


def _read(path):
    try:
        with Path(path).open('rb') as stream:
            data = stream.read(MAX_SETTINGS_BYTES + 1)
        if len(data) > MAX_SETTINGS_BYTES:
            return ''
        return data.decode('utf-8')
    except (OSError, UnicodeError):
        return ''


def _chromium_folders(root, default):
    root = Path(root)
    preferences = [root / 'Preferences']  # Opera can store its main profile here.
    try:
        preferences.extend(child / 'Preferences' for child in root.iterdir() if child.is_dir())
    except OSError:
        return
    for preference in preferences:
        raw = _read(preference)
        if not raw:
            continue
        try:
            data = json.loads(raw)
            if not isinstance(data, dict):
                continue
            download = data.get('download', {})
            if not isinstance(download, dict):
                continue
            folder = download.get('default_directory') or default
            if isinstance(folder, (str, Path)):
                yield folder, preference.parent.name
        except (ValueError, TypeError):
            continue


_PREF = re.compile(r'^\s*user_pref\(\s*("(?:[^"\\]|\\.)*")\s*,\s*(.*?)\s*\);\s*$')


def _firefox_folders(root, default, desktop):
    root = Path(root)
    profiles = set()
    config = configparser.ConfigParser(interpolation=None)
    try:
        config.read_string(_read(root / 'profiles.ini'))
        for section in config.sections():
            if section.startswith('Profile') and config.has_option(section, 'Path'):
                profile = Path(config.get(section, 'Path'))
                if config.get(section, 'IsRelative', fallback='1') == '1':
                    profile = root / profile
                if profile.is_absolute():
                    profiles.add(profile)
    except (configparser.Error, ValueError):
        pass
    # Standard profiles may be available even if profiles.ini is missing.
    for parent in (root, root / 'Profiles'):
        try:
            profiles.update(child for child in parent.iterdir()
                            if child.is_dir() and (child / 'prefs.js').is_file())
        except OSError:
            pass
    for profile in sorted(profiles):
        preferences = {}
        found = False
        for name in ('prefs.js', 'user.js'):
            raw = _read(profile / name)
            found = found or bool(raw)
            for line in raw.splitlines():
                match = _PREF.match(line)
                if not match:
                    continue
                try:
                    key, value = json.loads(match[1]), json.loads(match[2])
                except ValueError:
                    continue
                if key in ('browser.download.dir', 'browser.download.folderList'):
                    preferences[key] = value
        if not found:
            continue
        mode = preferences.get('browser.download.folderList', 1)
        folder = (preferences.get('browser.download.dir') if mode == 2 else
                  desktop if mode == 0 else default if mode == 1 else None)
        if isinstance(folder, (str, Path)):
            yield folder, profile.name


def settings_signature(platform_backend=None):
    """Modification times of the files that name download folders.

    Cheap enough to check every few seconds; folders are searched again only when
    it changes, for example after choosing another download folder in a browser.
    """
    platform_backend = platform_backend or backend
    files = [platform_backend.user_directories_file()]
    for _label, root, kind in platform_backend.browser_profile_locations():
        root = Path(root)
        files += [root / 'profiles.ini'] if kind == 'firefox' else [root / 'Preferences']
        try:
            profiles = [child for child in root.iterdir() if child.is_dir()]
        except OSError:
            continue
        for profile in profiles:
            files += [profile / 'prefs.js', profile / 'user.js'] if kind == 'firefox' else [profile / 'Preferences']
    signature = []
    for path in files:
        if path is None:
            continue
        try:
            signature.append((str(path), path.stat().st_mtime_ns))
        except OSError:
            continue
    return tuple(signature)


def discover_download_folders(platform_backend=None):
    """Return existing folders with combined source labels, without duplicates."""
    platform_backend = platform_backend or backend
    folders = {}

    def add(path, source):
        if not isinstance(path, (str, Path)) or not str(path) or not os.path.isabs(path):
            return
        try:
            canonical = os.path.realpath(path)
            if not Path(canonical).is_dir():
                return
        except (OSError, ValueError):
            return
        key = os.path.normcase(canonical)
        if key not in folders:
            folders[key] = (canonical, [])
        if source not in folders[key][1]:
            folders[key][1].append(source)

    default = platform_backend.downloads_directory()
    desktop = platform_backend.desktop_directory()
    add(default, 'System Downloads')
    for label, root, kind in platform_backend.browser_profile_locations():
        candidates = (_firefox_folders(root, default, desktop) if kind == 'firefox'
                      else _chromium_folders(root, default))
        for path, profile in candidates:
            add(path, f'{label} — {profile}')
    return [DownloadFolder(path, tuple(sources)) for path, sources in folders.values()]
