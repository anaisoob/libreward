"""Settings an administrator sets for every user of the computer.

/etc/libreward/policy.json on Linux, written by root, for example on a
children's computer or in an organisation:

    {
      "settings": {"watch_folders_enabled": true, "scheduled_scan": "weekly"},
      "dangerous_files": "quarantine"
    }

`settings` take the place of the user's own and cannot be changed in LibreWard;
`dangerous_files: quarantine` removes "Keep file" from the threat question and
restoring from quarantine. A file that another user could have written is not a
policy and is ignored. Users can still stop programs running under their own
account; the policy makes LibreWard itself keep its protection on.
"""
import json
import os
import stat

from backends import backend

SETTINGS = {
    'watch_folders_enabled': lambda value: isinstance(value, bool),
    'follow_download_folders': lambda value: isinstance(value, bool),
    'watched_folders': lambda value: isinstance(value, list) and all(isinstance(item, str) and item for item in value),
    'notify_threats_only': lambda value: isinstance(value, bool),
    'scheduled_scan': lambda value: value in ('off', 'daily', 'weekly'),
    'auto_update_database': lambda value: isinstance(value, bool),
}
DANGEROUS_FILES = ('ask', 'quarantine')
MAX_BYTES = 64 * 1024


def _trusted(path):
    """Owned by root and writable by nobody else, like its folder."""
    for item in (path, path.parent):
        info = os.stat(item)
        if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return False
    return True


def load_policy():
    """{'settings': {...}, 'dangerous_files': 'ask'|'quarantine'}; empty settings without a policy."""
    policy = {'settings': {}, 'dangerous_files': 'ask'}
    path = backend.policy_file()
    if path is None:
        return policy
    try:
        if not path.is_file() or not _trusted(path):
            return policy
        with path.open('rb') as stream:
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            return policy
        data = json.loads(raw)
    except (OSError, ValueError):
        return policy
    if not isinstance(data, dict):
        return policy
    settings = data.get('settings')
    if isinstance(settings, dict):
        policy['settings'] = {key: value for key, value in settings.items()
                              if key in SETTINGS and SETTINGS[key](value)}
    folders = policy['settings'].get('watched_folders')
    if folders is not None:
        # "~/Downloads" means each user's own folder.
        policy['settings']['watched_folders'] = [os.path.expanduser(folder) for folder in folders]
    if data.get('dangerous_files') in DANGEROUS_FILES:
        policy['dangerous_files'] = data['dangerous_files']
    return policy


def apply_policy(config, policy=None):
    """The user's settings with the administrator's in their place."""
    settings = (policy or load_policy())['settings']
    if not settings:
        return config
    return dict(config or {}, **settings)


def policy_signature():
    """Changes when the policy file changes, so the background service reads it again."""
    path = backend.policy_file()
    try:
        info = path.stat() if path is not None else None
    except OSError:
        return None
    return (info.st_mtime_ns, info.st_size) if info else None
