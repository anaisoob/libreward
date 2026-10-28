"""Security status: the most important protection of this computer in plain words.

The platform backend reads the facts (backends/linux_security.py on Linux);
this module decides what each one means. Every item is a dict with key, title,
detail, severity ('ok', 'warning' or 'info') and action: (button text, action
key) or None. The window performs the actions.
"""
import time

UPDATE_COMMANDS = {'apt': 'sudo apt update && sudo apt upgrade', 'dnf': 'sudo dnf upgrade',
                   'zypper': 'sudo zypper update', 'pacman': 'sudo pacman -Syu'}
# Older than this, installing updates needs attention.
UPDATE_DAYS = 14


def item(key, title, detail, severity='ok', action=None):
    return {'key': key, 'title': title, 'detail': detail, 'severity': severity, 'action': action}


def _days(seconds):
    days = int(seconds // 86400)
    return 'today' if days < 1 else 'yesterday' if days < 2 else f'{days} days ago'


def updates_item(facts, now):
    if facts.get('automatic_updates'):
        return item('updates', 'System updates install automatically',
                    'Updates close security holes that attackers use.')
    last = facts.get('last_update')
    if not isinstance(last, (int, float)):
        return item('updates', 'Could not tell when the system was last updated',
                    'Install system updates regularly: they close security holes that attackers use.', 'info')
    action = ('Open software updates', 'updates') if facts.get('update_program') else None
    command = UPDATE_COMMANDS.get(facts.get('pkg_manager'))
    how = '' if action or not command else f' In a terminal: {command}'
    if now - last <= UPDATE_DAYS * 86400:
        return item('updates', f'System updated {_days(now - last)}',
                    'Updates close security holes that attackers use. Keep installing them regularly.')
    return item('updates', f'System not updated for {int((now - last) // 86400)} days',
                'Updates close security holes that attackers use. Install the available updates.' + how,
                'warning', action)


def ports_item(facts):
    desktop_ports = set(facts.get('desktop_ports') or ())
    ports = facts.get('listening_ports') or []
    names = facts.get('port_names', {})
    reachable = [port for port in ports if port not in desktop_ports]
    if not reachable:
        return item('network', 'No programs wait for connections from other computers',
                    'Other computers on the network cannot connect to programs on this one.'
                    if not ports else 'Only usual desktop services are reachable on the local network.')
    listed = ', '.join(f"{names.get(port, 'a program')} (port {port})" for port in reachable[:5])
    listed = listed[0].upper() + listed[1:]
    more = f' and {len(reachable) - 5} more' if len(reachable) > 5 else ''
    title = (f'{len(reachable)} program{"s" if len(reachable) > 1 else ""} wait'
             f'{"" if len(reachable) > 1 else "s"} for connections from other computers')
    if facts.get('firewall') is True:
        return item('network', title, f'{listed}{more}. The firewall decides which of them other computers can '
                    'reach. If you do not use one, turn it off or uninstall it.', 'info')
    return item('network', title, f'{listed}{more}. Without a firewall, other computers on the network can try to '
                'connect to them. Turn on the firewall, or turn off what you do not use.', 'warning',
                ('Open Firewall', 'firewall'))


def security_items(facts, *, websites_available, websites_on, files_on, scanning_ready, now=None):
    """Items for the page; facts from the backend, the rest from LibreWard itself."""
    now = time.time() if now is None else now
    items = [updates_item(facts, now)]
    firewall = facts.get('firewall')
    if firewall is True:
        items.append(item('firewall', 'Firewall is on',
                          'Connections from other computers that you did not ask for are blocked.'))
    else:
        items.append(item('firewall', 'Firewall is off' if firewall is False else 'No firewall is installed',
                          'A firewall blocks connections from other computers that you did not ask for.',
                          'warning', ('Open Firewall', 'firewall')))
    if websites_available:
        items.append(item('websites', 'Dangerous websites are blocked',
                          'Known scam, phishing and malware websites do not open.') if websites_on else
                     item('websites', 'Dangerous websites are not blocked',
                          'Internet protection stops known scam, phishing and malware websites from opening.',
                          'warning', ('Turn on', 'internet')))
    items.append(item('files', 'New downloads are checked for viruses',
                      'Live protection checks new files as soon as they arrive.') if files_on else
                 item('files', 'New downloads are not checked for viruses',
                      'Live protection checks new downloads as soon as they arrive, also when LibreWard is closed.',
                      'warning', ('Turn on', 'internet')))
    items.append(item('antivirus', 'Virus scanning is ready', 'The antivirus engine and virus database are '
                      'installed.') if scanning_ready else
                 item('antivirus', 'Virus scanning needs setup', 'The antivirus engine or the virus database is '
                      'missing, so files cannot be checked.', 'warning', ('Set up', 'setup')))
    items.append(ports_item(facts))
    if facts.get('screen_lock') is not None:
        items.append(item('screen-lock', 'Screen locks when you are away',
                          'Nobody can use your account while you are away from the computer.')
                     if facts['screen_lock'] else
                     item('screen-lock', 'Screen does not lock by itself',
                          'Anyone at the computer can use your account while you are away. LibreWard can lock the '
                          'screen after five minutes without use.', 'warning', ('Turn on', 'screen-lock')))
    if facts.get('disk_encrypted') is not None:
        items.append(item('disk', 'Your files are encrypted on disk',
                          'If this computer is lost or stolen, others cannot read your files.')
                     if facts['disk_encrypted'] else
                     item('disk', 'Your files are not encrypted on disk',
                          'If this computer is lost or stolen, others can read your files. Encryption is chosen '
                          'when the system is installed.', 'info'))
    if facts.get('administrator') is not None:
        items.append(item('account', 'This account can change system settings',
                          'That is normal for your own computer. Children, and people who should not change '
                          'settings, are safer with an account without administrator rights.', 'info')
                     if facts['administrator'] else
                     item('account', 'This account cannot change system settings',
                          'Changing protection that affects the whole computer needs the administrator password.'))
    return items


def summary(items):
    """(title, severity) for the top of the page."""
    count = sum(entry['severity'] == 'warning' for entry in items)
    if not count:
        return 'This computer is well protected', 'success'
    return f'{count} thing{"s" if count > 1 else ""} need{"" if count > 1 else "s"} your attention', 'warning'
