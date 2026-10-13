"""Run as root by package removal: turn Internet protection off and remove
LibreWard's system files (/etc/libreward, its systemd units and DNS snippets).

    /usr/bin/python3 -I /usr/share/libreward/system_cleanup.py
"""
import os
import sys

# -I leaves the script directory off sys.path; the app modules live next to it.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backends.linux_dns_service import system_cleanup  # noqa: E402

if __name__ == '__main__':
    sys.exit(system_cleanup())
