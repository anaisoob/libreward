"""Security status: the most important protection of this computer in plain words.

The platform backend reads the facts (backends/linux_security.py on Linux);
this module decides what each one means. Every item is a dict with key, title,
detail, severity ('ok', 'warning' or 'info'), action: (button text, action key)
or None, and label and state: the same in a few words. The window performs the
actions.
"""
import time

UPDATE_COMMANDS = {'apt': 'sudo apt update && sudo apt upgrade', 'dnf': 'sudo dnf upgrade',
                   'zypper': 'sudo zypper update', 'pacman': 'sudo pacman -Syu'}
# Older than this, installing updates needs attention.
UPDATE_DAYS = 14
# New viruses appear daily; older than this, the database needs attention.
DATABASE_DAYS = 3
# Longer than the longest scheduled scan interval (a week), so that only
# scans that really stopped happening are reported.
SCAN_DAYS = 14
LABELS = {'updates': 'System updates', 'firewall': 'Firewall', 'websites': 'Dangerous websites',
          'files': 'New downloads', 'antivirus': 'Virus scanning', 'network': 'Other computers',
          'screen-lock': 'Screen lock', 'disk': 'Disk encryption', 'account': 'This account',
          'database': 'Virus database', 'scan': 'Last scan'}
# What to fix first: without a working scanner nothing else about viruses helps.
FIX_ORDER = ('antivirus', 'database', 'files', 'firewall', 'network', 'scan', 'updates', 'websites', 'screen-lock')


def item(key, title, detail, severity='ok', action=None, *, state):
    return {'key': key, 'title': title, 'detail': detail, 'severity': severity, 'action': action,
            'label': LABELS[key], 'state': state}


def _days(seconds):
    days = int(seconds // 86400)
    return 'today' if days < 1 else 'yesterday' if days < 2 else f'{days} days ago'


def updates_item(facts, now):
    if facts.get('automatic_updates'):
        return item('updates', 'System updates install automatically',
                    'Updates close security holes that attackers use.', state='Install automatically')
    last = facts.get('last_update')
    if not isinstance(last, (int, float)):
        return item('updates', 'Could not tell when the system was last updated',
                    'Install system updates regularly: they close security holes that attackers use.', 'info',
                    state='Not known')
    action = ('Open software updates', 'updates') if facts.get('update_program') else None
    command = UPDATE_COMMANDS.get(facts.get('pkg_manager'))
    how = '' if action or not command else f' In a terminal: {command}'
    if now - last <= UPDATE_DAYS * 86400:
        return item('updates', f'System updated {_days(now - last)}',
                    'Updates close security holes that attackers use. Keep installing them regularly.',
                    state=f'Updated {_days(now - last)}')
    return item('updates', f'System not updated for {int((now - last) // 86400)} days',
                'Updates close security holes that attackers use. Install the available updates.' + how,
                'warning', action, state=f'{int((now - last) // 86400)} days old')


def ports_item(facts):
    desktop_ports = set(facts.get('desktop_ports') or ())
    ports = facts.get('listening_ports') or []
    names = facts.get('port_names', {})
    reachable = [port for port in ports if port not in desktop_ports]
    if not reachable:
        return item('network', 'No programs wait for connections from other computers',
                    'Other computers on the network cannot connect to programs on this one.'
                    if not ports else 'Only usual desktop services are reachable on the local network.',
                    state='Cannot reach programs')
    listed = ', '.join(f"{names.get(port, 'a program')} (port {port})" for port in reachable[:5])
    listed = listed[0].upper() + listed[1:]
    more = f' and {len(reachable) - 5} more' if len(reachable) > 5 else ''
    title = (f'{len(reachable)} program{"s" if len(reachable) > 1 else ""} wait'
             f'{"" if len(reachable) > 1 else "s"} for connections from other computers')
    state = f'Can reach {len(reachable)} program{"s" if len(reachable) > 1 else ""}'
    if facts.get('firewall') is True:
        return item('network', title, f'{listed}{more}. The firewall decides which of them other computers can '
                    'reach. If you do not use one, turn it off or uninstall it.', 'info',
                    state=state)
    return item('network', title, f'{listed}{more}. Without a firewall, other computers on the network can try to '
                'connect to them. Turn on the firewall, or turn off what you do not use.', 'warning',
                ('Open Firewall', 'firewall'), state=state)


def security_items(facts, *, websites_available, websites_on, files_on, scanning_ready, now=None):
    """Items for the page; facts from the backend, the rest from LibreWard itself."""
    now = time.time() if now is None else now
    items = [updates_item(facts, now)]
    firewall = facts.get('firewall')
    if firewall is True:
        items.append(item('firewall', 'Firewall is on',
                          'Connections from other computers that you did not ask for are blocked.', state='On'))
    else:
        items.append(item('firewall', 'Firewall is off' if firewall is False else 'No firewall is installed',
                          'A firewall blocks connections from other computers that you did not ask for.',
                          'warning', ('Open Firewall', 'firewall'),
                          state='Off' if firewall is False else 'Not installed'))
    if websites_available:
        items.append(item('websites', 'Dangerous websites are blocked',
                          'Known scam, phishing and malware websites do not open.', state='Blocked')
                     if websites_on else
                     item('websites', 'Dangerous websites are not blocked',
                          'Internet protection stops known scam, phishing and malware websites from opening.',
                          'warning', ('Turn on', 'internet'), state='Not blocked'))
    items.append(item('files', 'New downloads are checked for viruses',
                      'Live protection checks new files as soon as they arrive.', state='Checked')
                 if files_on else
                 item('files', 'New downloads are not checked for viruses',
                      'Live protection checks new downloads as soon as they arrive, also when LibreWard is closed.',
                      'warning', ('Turn on', 'internet'), state='Not checked'))
    items.append(item('antivirus', 'Virus scanning is ready', 'The antivirus engine and virus database are '
                      'installed.', state='Ready') if scanning_ready else
                 item('antivirus', 'Virus scanning needs setup', 'The antivirus engine or the virus database is '
                      'missing, so files cannot be checked.', 'warning', ('Set up', 'setup'),
                      state='Needs setup'))
    items.append(ports_item(facts))
    if facts.get('screen_lock') is not None:
        items.append(item('screen-lock', 'Screen locks when you are away',
                          'Nobody can use your account while you are away from the computer.',
                          state='Locks by itself')
                     if facts['screen_lock'] else
                     item('screen-lock', 'Screen does not lock by itself',
                          'Anyone at the computer can use your account while you are away. LibreWard can lock the '
                          'screen after five minutes without use.', 'warning', ('Turn on', 'screen-lock'),
                          state='Does not lock'))
    if facts.get('disk_encrypted') is not None:
        items.append(item('disk', 'Your files are encrypted on disk',
                          'If this computer is lost or stolen, others cannot read your files.',
                          state='Your files are encrypted')
                     if facts['disk_encrypted'] else
                     item('disk', 'Your files are not encrypted on disk',
                          'If this computer is lost or stolen, others can read your files. Encryption is chosen '
                          'when the system is installed.', 'info', state='Your files are not encrypted'))
    if facts.get('administrator') is not None:
        items.append(item('account', 'This account can change system settings',
                          'That is normal for your own computer. Children, and people who should not change '
                          'settings, are safer with an account without administrator rights.', 'info',
                          state='Can change system settings')
                     if facts['administrator'] else
                     item('account', 'This account cannot change system settings',
                          'Changing protection that affects the whole computer needs the administrator password.',
                          state='Cannot change system settings'))
    return items


def summary(items):
    """(title, severity) for the top of the page."""
    count = sum(entry['severity'] == 'warning' for entry in items)
    if not count:
        return 'This computer is well protected', 'success'
    return f'{count} thing{"s" if count > 1 else ""} need{"" if count > 1 else "s"} your attention', 'warning'


def old_database_days(database_time, now=None):
    """Age in days of a database that is too old, otherwise None."""
    now = time.time() if now is None else now
    if not database_time or now - database_time <= DATABASE_DAYS * 86400:
        return None
    return int((now - database_time) // 86400)


def upkeep_items(database_time, scan_time, *, scanning_ready, can_update_database, now=None):
    """Things that go out of date; shown only when they have. Recent dates are in activity()."""
    now = time.time() if now is None else now
    items = []
    days = old_database_days(database_time, now)
    if days is not None:
        items.append(item('database', f'Virus database is {days} days old',
                          'New viruses are not recognised until the database is updated.', 'warning',
                          ('Update virus database', 'database') if can_update_database else ('Set up', 'setup'),
                          state=f'{days} days old'))
    if not scanning_ready:
        return items  # 'Virus scanning needs setup' says what to do first
    if not scan_time:
        items.append(item('scan', 'This computer has not been scanned yet',
                          'A Quick scan checks the places where harmful files usually are.', 'warning',
                          ('Scan now', 'scan'), state='No scan yet'))
    elif now - scan_time > SCAN_DAYS * 86400:
        days = int((now - scan_time) // 86400)
        items.append(item('scan', f'Last scan was {days} days ago',
                          'A Quick scan checks the places where harmful files usually are.', 'warning',
                          ('Scan now', 'scan'), state=f'{days} days ago'))
    return items


def attention(items):
    """The items that need the user, the one to fix first at the top."""
    return sorted((entry for entry in items if entry['severity'] == 'warning'),
                  key=lambda entry: FIX_ORDER.index(entry['key']))


def activity(database_time, scan_time, quarantined, now=None):
    """One line about what LibreWard has been doing; a time is None when unknown."""
    now = time.time() if now is None else now
    parts = [f'Virus database updated {_days(now - database_time)}'] if database_time else []
    parts.append(f'Last scan {_days(now - scan_time)}' if scan_time else 'No scan yet')
    if quarantined:
        parts.append(f'{quarantined} file{"s" if quarantined > 1 else ""} in quarantine')
    return ' · '.join(parts)
