"""What the root programs of an installed LibreWard do, one for each polkit action.

A package installs a small program per action in /usr/libexec/libreward
(packaging/libreward-root.in) and the actions in
/usr/share/polkit-1/actions/io.github.anaisoob.LibreWard.policy, so the password
dialog says what LibreWard wants to do and an administrator can allow or forbid
each action with polkit rules. The programs import this module from the
application folder, which only root can change.

Arguments come from a process of the user: each action accepts only fixed
choices, validates them with the same code as the application and finds the
system programs it runs itself.
"""
import json
import os
import subprocess
import sys


def system_check(arguments):
    from backends import backend
    from backends.linux_system_check import run_root_checks
    if arguments:
        raise ValueError('The system check takes no arguments.')
    settings = backend.deep_check_settings()
    findings, ran = run_root_checks(settings['manager'], settings['tools'])
    print(json.dumps({'findings': findings, 'checks': ran}))
    return 0


def internet_protection(arguments):
    """Arguments: none to pause, or the mode and the DNS service; the domain list on stdin."""
    from backends import backend
    source = backend.internet_protection_source()
    sys.argv = ['internet-protection', *arguments]
    exec(compile(source, 'internet-protection', 'exec'), {'__name__': '__main__'})  # noqa: S102 - LibreWard's own code
    return 0


def firewall_read(arguments):
    """Argument: the firewall tool, for example UFW."""
    from backends import backend
    if len(arguments) != 1:
        raise ValueError('Choose one firewall tool.')
    for command in backend.firewall_read_commands(arguments[0]):
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, env={**os.environ, 'LC_ALL': 'C'}, check=False)
        sys.stdout.buffer.write(result.stdout)
        sys.stdout.flush()
        if result.returncode:
            return result.returncode
    return 0


def firewall_change(arguments):
    """Arguments: the change as JSON and the marker of its output.

    {"tool": "UFW", "enabled": true}, {"tool": ..., "rule": {...}} or
    {"tool": ..., "removal": {...}} with the fields of FirewallRule or FirewallRemoval.
    """
    from backends import backend
    from core.firewall import FirewallRemoval, FirewallRule
    if len(arguments) != 2:
        raise ValueError('Invalid firewall change.')
    request = json.loads(arguments[0])
    if not isinstance(request, dict) or len(request) != 2 or not isinstance(request.get('tool'), str):
        raise ValueError('Invalid firewall change.')
    changes = {}
    if isinstance(request.get('rule'), dict):
        changes['rule'] = FirewallRule(**request['rule'])
    elif isinstance(request.get('removal'), dict):
        changes['removal'] = FirewallRemoval(**request['removal'])
    elif isinstance(request.get('enabled'), bool):
        changes['enabled'] = request['enabled']
    else:
        raise ValueError('Invalid firewall change.')
    shell, script, _read = backend.firewall_change_script(request['tool'], marker=arguments[1], **changes)
    sys.stdout.flush()
    os.execv(shell, [shell, '-c', script])


ACTIONS = {
    'system-check': system_check,
    'internet-protection': internet_protection,
    'firewall-read': firewall_read,
    'firewall-change': firewall_change,
}


def main(action, arguments):
    try:
        if os.geteuid() != 0:
            raise PermissionError('This LibreWard program runs as root through pkexec.')
        return ACTIONS[action](arguments)
    except Exception as exc:  # noqa: BLE001 - reported to the application, never a traceback
        print(str(exc), file=sys.stderr)
        return 1
