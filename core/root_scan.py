"""Check, with administrator rights, the files a scan could not open."""
from backends import backend
from backends.linux_root_scan import MAX_REQUEST
from scanner import _first_database_dir


def limited(paths):
    """As many paths as one request holds; (paths, how many were left out)."""
    kept, size = [], 200  # the rest of the request
    for path in paths:
        size += len(path.encode('utf-8', 'surrogateescape')) * 2 + 4  # at worst escaped
        if size > MAX_REQUEST:
            break
        kept.append(path)
    return kept, len(paths) - len(kept)


def found_in(line):
    """(path, threat) of a clamscan result line, otherwise None."""
    text = line.strip()
    if not text.endswith(' FOUND') or ': ' not in text:
        return None
    path, threat = text[:-len(' FOUND')].rsplit(': ', 1)
    return path, threat


def checked_file(line):
    """The path in a clamscan result line, otherwise ''."""
    text = line.strip()
    for ending in (': OK', ' FOUND'):
        if text.endswith(ending):
            return text[:-len(ending)].rsplit(': ', 1)[0] if ending == ' FOUND' else text[:-len(ending)]
    return ''


def check_as_administrator(paths, log, progress=lambda _count, _path: None):
    """Asks for the password; raises AuthorizationError when refused or cancelled.

    `progress` hears (files checked so far, the last file) from the worker.
    """
    paths, left_out = limited(paths)
    infected = []
    files = 0
    for path in paths[:100]:
        log(f'To check: {path}')

    def line_of_output(line):
        nonlocal files
        log(line)
        found = found_in(line)
        if found:
            infected.append(found)
        path = checked_file(line)
        if path:
            files += 1
            progress(files, path)

    database = _first_database_dir()
    code, stopped = backend.scan_as_root(paths, str(database) if database else None, line_of_output)
    log(f'Checked {files:,} file{"s" if files != 1 else ""}.')
    return {'checked': len(paths), 'files': files, 'left_out': left_out, 'infected': infected, 'stopped': stopped,
            'complete': code in (0, 1)}


def outcome(result):
    """(title, text, is it a warning) for a finished check."""
    if result.get('stopped'):
        return 'Check stopped', 'Files checked so far are listed under Show details.', False
    infected, checked = result['infected'], result['checked']
    files = result.get('files', 0)
    place = f'{files:,} file{"s" if files != 1 else ""} in {checked} skipped location{"s" if checked != 1 else ""}'
    if infected:
        return (f'{len(infected)} dangerous file{"s" if len(infected) != 1 else ""} found',
                ('They are listed under Detected files. Moving them to quarantine asks for the administrator '
                 'password.'), True)
    if not result['complete']:
        return 'The check did not finish', 'See Show details for what happened.', True
    if not files:
        return ('Nothing to check', f'The {checked} skipped location{"s" if checked != 1 else ""} '
                'hold no files that can be checked. Show details lists them.', False)
    more = f' {result["left_out"]} more could not be included; check them separately.' if result['left_out'] else ''
    return 'No threats found', f'LibreWard checked {place} with administrator rights.{more}', False
