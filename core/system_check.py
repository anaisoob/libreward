"""System check: signs of a hidden intruder, in plain words.

The platform backend does the checks (backends/linux_system_check.py on Linux).
Findings are suspicious, not proven threats: nothing is moved or deleted.
"""
import time

from backends import backend

NOTE = ('This check looks for signs of hidden programs that your user account can see. It cannot prove '
        'that the computer is clean: an intruder in the system core can hide from any check that runs on '
        'the same computer. Programs of other users and system files are not checked.')


def available():
    return backend.system_check_available()


def run_system_check():
    """{'time', 'findings', 'checks'}, or None where the platform has no system check."""
    outcome = backend.system_check()
    if outcome is None:
        return None
    findings, checks = outcome
    return {'time': time.time(), 'findings': findings, 'checks': checks}


def summary(result):
    """(title, severity) of a finished check."""
    count = len(result['findings'])
    if not count:
        return 'Nothing suspicious found', 'success'
    return (f'LibreWard found {count} thing{"s" if count > 1 else ""} to look at', 'warning')


def notification(result):
    """(title, message) for a check that found something."""
    titles = [entry['title'] for entry in result['findings']]
    more = f' (+{len(titles) - 1} more)' if len(titles) > 1 else ''
    return ('⚠ LibreWard — something suspicious found',
            f'{titles[0]}{more}.\nOpen LibreWard and choose System check on the Virus scan page.')
