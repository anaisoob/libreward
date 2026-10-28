"""Facts about the system's security settings that a normal user can read.

Used by the Security status page (core/security_status.py turns them into plain
words). Nothing here changes the system except the screen lock, which is a
per-user desktop setting. Paths and commands are parameters for tests.
"""
import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path

# TCP ports that are expected on a desktop and harmless to reach on a local network.
DESKTOP_PORTS = {5355: 'local name lookup (LLMNR)', **{port: 'KDE Connect' for port in range(1714, 1765)}}
PORT_NAMES = {21: 'file transfer (FTP)', 22: 'remote login (SSH)', 23: 'remote login (Telnet)',
              25: 'mail server', 53: 'name server (DNS)', 80: 'web server', 111: 'network file service (rpcbind)',
              139: 'Windows file sharing', 443: 'web server', 445: 'Windows file sharing', 631: 'printing (CUPS)',
              2049: 'network files (NFS)', 3306: 'database (MySQL)', 3389: 'remote desktop (RDP)',
              5432: 'database (PostgreSQL)', 5900: 'screen sharing (VNC)', 8080: 'web server',
              **DESKTOP_PORTS}


def _run(command, timeout=10):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                                stdin=subprocess.DEVNULL, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None, ''
    return result.returncode, result.stdout


def _read(path):
    try:
        return Path(path).read_text(encoding='utf-8', errors='replace')
    except OSError:
        return None


# ── system updates ─────────────────────────────────────────────────

def automatic_updates(manager, *, apt_config='/etc/apt/apt.conf.d', systemctl=None):
    """True or False; None where the system has no standard automatic updates (Arch)."""
    if manager == 'dpkg':
        text = ''.join(_read(path) or '' for path in sorted(Path(apt_config).glob('*'))) if Path(apt_config).is_dir() else ''
        return bool(re.search(r'APT::Periodic::Unattended-Upgrade\s+"1"', text))
    if manager == 'rpm':
        systemctl = systemctl or shutil.which('systemctl')
        if not systemctl:
            return False
        timers = ('dnf-automatic.timer', 'dnf-automatic-install.timer', 'dnf5-automatic.timer')
        return any(_run([systemctl, 'is-enabled', '--quiet', timer])[0] == 0 for timer in timers)
    return None


def last_update(manager, *, dpkg_log='/var/log/dpkg.log', pacman_log='/var/log/pacman.log', rpm=None):
    """When packages were last upgraded (time.time() value), or None."""
    if manager == 'dpkg':
        times = re.findall(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) upgrade ', _read(dpkg_log) or '', re.MULTILINE)
        return datetime.strptime(times[-1], '%Y-%m-%d %H:%M:%S').timestamp() if times else None
    if manager == 'pacman':
        times = re.findall(r'^\[([^\]]+)\] \[PACMAN\] starting full system upgrade', _read(pacman_log) or '',
                           re.MULTILINE)
        if not times:
            return None
        try:
            return datetime.fromisoformat(times[-1].replace('Z', '+00:00')).timestamp()
        except ValueError:
            return None
    if manager == 'rpm':
        rpm = rpm or shutil.which('rpm')
        code, output = _run([rpm, '-qa', '--qf', '%{INSTALLTIME}\\n'], timeout=30) if rpm else (None, '')
        times = [int(line) for line in output.split() if line.isdigit()]
        return max(times) if code == 0 and times else None
    return None


def update_program():
    """Command that opens the desktop's software updates, or None."""
    for command in (['gnome-software', '--mode=updates'], ['plasma-discover', '--mode', 'Update'],
                    ['mintupdate'], ['update-manager']):
        if shutil.which(command[0]):
            return command
    return None


# ── network ────────────────────────────────────────────────────────

def _loopback(address, version):
    if version == 4:
        return int(address, 16).to_bytes(4, 'little')[0] == 127
    raw = bytes.fromhex(address)
    words = b''.join(raw[index:index + 4][::-1] for index in range(0, 16, 4))
    return words == bytes(15) + b'\x01' or (words[:12] == bytes(10) + b'\xff\xff' and words[12] == 127)


def listening_ports(proc='/proc'):
    """TCP ports that accept connections from other computers (not only from this one)."""
    ports = set()
    for name, version in (('tcp', 4), ('tcp6', 6)):
        for line in (_read(Path(proc) / 'net' / name) or '').splitlines()[1:]:
            fields = line.split()
            if len(fields) < 4 or fields[3] != '0A':  # LISTEN
                continue
            address, port = fields[1].split(':')
            if not _loopback(address, version):
                ports.add(int(port, 16))
    return sorted(ports)


def firewall_enabled(*, ufw_config='/etc/ufw/ufw.conf', firewall_cmd=None):
    """True or False when a firewall tool is installed; None without one."""
    firewall_cmd = firewall_cmd if firewall_cmd is not None else shutil.which('firewall-cmd')
    if firewall_cmd:
        code, output = _run([firewall_cmd, '--state'], timeout=10)
        if output.strip() == 'running':
            return True
    ufw = _read(ufw_config)
    if ufw is not None:
        return bool(re.search(r'^\s*ENABLED\s*=\s*yes\s*$', ufw, re.MULTILINE))
    return False if firewall_cmd else None


# ── this computer and account ──────────────────────────────────────

def disk_encrypted(lsblk=None):
    """True when / or /home is on an encrypted (LUKS) device; None when unknown."""
    lsblk = lsblk or shutil.which('lsblk')
    code, output = _run([lsblk, '--json', '-o', 'NAME,TYPE,MOUNTPOINTS'], timeout=10) if lsblk else (None, '')
    if code != 0:
        return None
    try:
        devices = json.loads(output).get('blockdevices', [])
    except ValueError:
        return None
    found = {}

    def walk(device, encrypted):
        encrypted = encrypted or device.get('type') == 'crypt'
        for point in device.get('mountpoints') or []:
            if point in ('/', '/home'):
                found[point] = encrypted
        for child in device.get('children') or []:
            walk(child, encrypted)

    for device in devices:
        walk(device, False)
    return found.get('/home', found.get('/')) if found else None


def administrator_account(groups=None):
    """Whether this account may change system settings (member of wheel, sudo or admin)."""
    import grp
    names = groups if groups is not None else {grp.getgrgid(group).gr_name for group in os.getgroups()}
    return bool(set(names) & {'wheel', 'sudo', 'admin'})


def screen_lock(desktop=None):
    """(desktop, locks) for GNOME or KDE; (None, None) elsewhere."""
    desktop = (desktop if desktop is not None else os.environ.get('XDG_CURRENT_DESKTOP', '')).lower()
    if 'gnome' in desktop and shutil.which('gsettings'):
        _code, enabled = _run(['gsettings', 'get', 'org.gnome.desktop.screensaver', 'lock-enabled'])
        _code, delay = _run(['gsettings', 'get', 'org.gnome.desktop.session', 'idle-delay'])
        if not enabled.strip():
            return 'gnome', None
        return 'gnome', enabled.strip() == 'true' and delay.split()[-1:] != ['0']
    if 'kde' in desktop:
        reader = shutil.which('kreadconfig6') or shutil.which('kreadconfig5')
        if reader:
            _code, value = _run([reader, '--file', 'kscreenlockerrc', '--group', 'Daemon', '--key', 'Autolock'])
            return 'kde', value.strip() != 'false'
    return None, None


def turn_on_screen_lock(desktop):
    """Lock the screen after five minutes without use; a setting of this user only."""
    if desktop == 'gnome':
        commands = [['gsettings', 'set', 'org.gnome.desktop.screensaver', 'lock-enabled', 'true']]
        _code, delay = _run(['gsettings', 'get', 'org.gnome.desktop.session', 'idle-delay'])
        if delay.split()[-1:] == ['0']:
            commands.append(['gsettings', 'set', 'org.gnome.desktop.session', 'idle-delay', '300'])
    elif desktop == 'kde':
        writer = shutil.which('kwriteconfig6') or shutil.which('kwriteconfig5') or 'kwriteconfig6'
        commands = [[writer, '--file', 'kscreenlockerrc', '--group', 'Daemon', '--key', 'Autolock', 'true']]
    else:
        raise OSError('The screen lock of this desktop cannot be changed here.')
    for command in commands:
        code, _output = _run(command)
        if code != 0:
            raise OSError('The screen lock setting could not be changed.')


def facts(manager):
    """Everything the Security status page shows from the system, read as this user."""
    desktop, locks = screen_lock()
    return {
        'automatic_updates': automatic_updates(manager),
        'last_update': last_update(manager),
        'update_program': update_program(),
        'listening_ports': listening_ports(),
        'firewall': firewall_enabled(),
        'disk_encrypted': disk_encrypted(),
        'administrator': administrator_account(),
        'desktop': desktop,
        'screen_lock': locks,
        'checked': time.time(),
    }
