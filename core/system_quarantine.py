"""Files that only an administrator may move, in the root-only system quarantine.

The contents stay with root (backends/linux_root_quarantine.py). This user's quarantine
folder keeps a note of each one, without contents, so the Quarantine page lists them
without asking for a password. Restoring and deleting ask for it.
"""
import json
import os

from backends import backend
from scanner import _first_database_dir


def needs_administrator(path):
    """Whether this account cannot take `path` away: it may not read it or remove it."""
    if not backend.root_quarantine_available():
        return False
    return not (os.access(path, os.R_OK) and os.access(os.path.dirname(path) or '.', os.W_OK | os.X_OK))


def is_gone(path):
    """A file in a folder this account cannot read is not gone, it just cannot be seen."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def _note_path(name):
    return backend.quarantine_dir() / (name + '.json')


def move(files, *, discard=False):
    """(path, success, message) of each (path, threat); asks for the password."""
    database = _first_database_dir()
    results = backend.quarantine_as_root({
        'action': 'move', 'items': [list(item) for item in files],
        'database': str(database) if database else None, 'discard': discard})
    report = []
    for (path, _threat), result in zip(files, results):
        if not result['ok']:
            report.append((path, False, f"Cannot move {path}: {result['error']}"))
        elif discard:
            report.append((path, True, f'Deleted: {path}'))
        else:
            metadata = result['metadata']
            backend.quarantine_dir().mkdir(parents=True, exist_ok=True)
            _note_path(metadata['quarantine_name']).write_text(json.dumps(metadata), encoding='utf-8')
            report.append((path, True, f'Quarantined: {path}'))
    return report


def _on_items(action, names, success):
    """(name, success, message); a note goes with its file."""
    results = backend.quarantine_as_root({'action': action, 'names': names})
    report = []
    for name, result in zip(names, results):
        if result['ok']:
            _note_path(name).unlink(missing_ok=True)
            report.append((name, True, f'{success}: {name}'))
        else:
            report.append((name, False, f"Cannot finish: {result['error']}"))
    return report


def restore(names):
    return _on_items('restore', names, 'Restored')


def delete(names):
    return _on_items('delete', names, 'Permanently deleted')
