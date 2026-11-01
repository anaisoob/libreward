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


def check_as_administrator(paths, log):
    """Asks for the password; raises AuthorizationError when refused or cancelled."""
    paths, left_out = limited(paths)
    infected = []

    def line_of_output(line):
        log(line)
        found = found_in(line)
        if found:
            infected.append(found)

    database = _first_database_dir()
    code, stopped = backend.scan_as_root(paths, str(database) if database else None, line_of_output)
    return {'checked': len(paths), 'left_out': left_out, 'infected': infected, 'stopped': stopped,
            'complete': code in (0, 1)}


def outcome(result):
    """(title, text, is it a warning) for a finished check."""
    infected, checked = result['infected'], result['checked']
    place = f'{checked} skipped location{"s" if checked != 1 else ""}'
    if infected:
        return (f'{len(infected)} dangerous file{"s" if len(infected) != 1 else ""} found',
                ('They are listed under Detected files. Your account cannot move or delete them, so LibreWard cannot '
                 'quarantine them. To remove them, use an administrator account.'), True)
    if not result['complete']:
        return 'The check did not finish', 'See Show details for what happened.', True
    more = f' {result["left_out"]} more could not be included; check them separately.' if result['left_out'] else ''
    return 'No threats found', f'LibreWard checked {place} with administrator rights.{more}', False
