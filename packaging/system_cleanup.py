"""Run as root by package removal: turn Internet protection off and remove
LibreWard's system files (/etc/libreward, its systemd units and DNS snippets).
When started through sudo or pkexec, also remove that user's folder monitoring
service (~/.config/systemd/user/libreward-monitor.service).

    /usr/bin/python3 -I /usr/share/libreward/system_cleanup.py
"""
import os
import sys

# -I leaves the script directory off sys.path; the app modules live next to it.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backends.linux import remove_user_monitor_service  # noqa: E402
from backends.linux_dns_service import system_cleanup  # noqa: E402


def invoking_user():
    """The user behind sudo or pkexec; None for root itself or package tools without one."""
    user = os.environ.get('SUDO_USER')
    if not user and os.environ.get('PKEXEC_UID', '').isdigit():
        import pwd
        try:
            user = pwd.getpwuid(int(os.environ['PKEXEC_UID'])).pw_name
        except KeyError:
            user = None
    return user if user and user != 'root' else None


if __name__ == '__main__':
    code = system_cleanup()
    user = invoking_user()
    message = remove_user_monitor_service(user) if user else None
    if message:
        print(message)
    sys.exit(code)
