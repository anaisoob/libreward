"""Virus check as root of files the user's account could not open.

Only what a scan skipped comes here, because root reading untrusted files is a
risk of its own. pkexec runs this program, so nothing from the request is trusted:
it names only files to check and a database folder, and this program finds
clamscan itself and chooses all its options. It reads and reports, it never
changes a file.

Standard library only: run from source, pkexec starts a trusted python3 -I with
this source, so root never imports files from a folder the user can change.

One line of JSON on stdin: {"database": folder or null, "paths": [...]}. Closing
stdin stops the check: the user's process may not signal one that runs as root.
The exit code is clamscan's: 0 clean, 1 found, anything else not completed.
"""
import json
import os
import stat
import subprocess
import sys
import threading

# Well below the size of a command line.
MAX_REQUEST = 1024 * 1024
FOLDERS = ('/usr/bin', '/usr/sbin', '/bin', '/sbin')
PSEUDO_FILESYSTEMS = ('/proc', '/sys', '/dev')
OPTIONS = ('--recursive', '--infected', '--no-summary', '--stdout',
           '--follow-dir-symlinks=0', '--follow-file-symlinks=0')


def trusted_clamscan(folders=FOLDERS):
    """clamscan from a system folder, where only root can change it or anything above it."""
    for folder in folders:
        path = os.path.realpath(os.path.join(folder, 'clamscan'))
        try:
            if not os.access(path, os.X_OK):
                continue
            current = path
            while True:
                status = os.stat(current)
                if status.st_uid or status.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                    break
                if current == '/':
                    return path
                current = os.path.dirname(current)
        except OSError:
            continue
    return None


def valid_path(path):
    return (isinstance(path, str) and os.path.isabs(path) and '\0' not in path and path != '/'
            and os.path.normpath(path) == path
            and not any(path == name or path.startswith(name + '/') for name in PSEUDO_FILESYSTEMS))


def read_request(line):
    """(database, paths) of a valid request; ValueError for anything else."""
    request = json.loads(line)
    if not isinstance(request, dict) or set(request) != {'database', 'paths'}:
        raise ValueError('Invalid request.')
    database, paths = request['database'], request['paths']
    if database is not None and not (valid_path(database) and os.path.isdir(database)):
        raise ValueError('Invalid database folder.')
    if not isinstance(paths, list) or not all(valid_path(path) for path in paths):
        raise ValueError('Invalid file list.')
    return database, paths


def clamscan_command(clamscan, database, paths):
    # Absolute paths cannot be read as options.
    return [clamscan, *OPTIONS, *([f'--database={database}'] if database else []), *paths]


def root_main():
    try:
        if os.geteuid() != 0:
            raise PermissionError('This LibreWard program runs as root through pkexec.')
        line = sys.stdin.readline(MAX_REQUEST + 1)
        if len(line) > MAX_REQUEST:
            raise ValueError('The file list is too long.')
        database, paths = read_request(line)
        clamscan = trusted_clamscan()
        if clamscan is None:
            raise OSError('clamscan was not found in a system folder.')
    except (OSError, ValueError) as exc:
        print(f'ERROR: {exc}', flush=True)
        return 2
    existing = [path for path in paths if os.path.exists(path) and not os.path.islink(path)]
    if not existing:
        return 0
    process = subprocess.Popen(clamscan_command(clamscan, database, existing), stdin=subprocess.DEVNULL,
                               stderr=subprocess.STDOUT, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})

    def stop_when_stdin_closes():
        sys.stdin.read()
        process.terminate()

    threading.Thread(target=stop_when_stdin_closes, daemon=True).start()
    return process.wait()
