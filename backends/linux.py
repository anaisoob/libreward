"""Linux platform backend.

ClamAV runtime detection order on Linux:

    1. system PATH (shutil.which) — standard ClamAV installation
    2. (No bundled/user-updated runtime on Linux in the initial version)

The backend still exposes the same data directory interface so that
future versions can support self-updating runtime on Linux too.
"""

import os
import platform as _platform
import re
import shutil
import signal
import subprocess
from pathlib import Path

from .base import PlatformBackend, RuntimeInfo


APP_NAME = "libreward"


def _parse_version(raw: str | None) -> str | None:
    """Extract version number from clamscan --version output."""
    if not raw:
        return None
    m = re.search(r"(\d+\.\d+\.\d+)", raw)
    return m.group(1) if m else None


class LinuxBackend(PlatformBackend):
    """Platform backend for Linux."""

    def clamd_endpoints(self):
        endpoints = [("unix", path) for path in (
            "/run/clamav/clamd.ctl", "/run/clamd.scan/clamd.sock",
            "/run/clamd/clamd.sock", "/tmp/clamd.socket")]
        for config in (Path('/etc/clamav/clamd.conf'), Path('/etc/clamd.d/scan.conf')):
            try:
                for line in config.read_text().splitlines():
                    parts = line.strip().split(maxsplit=1)
                    if len(parts) == 2 and parts[0] == 'LocalSocket':
                        endpoints.insert(0, ('unix', parts[1].strip('"')))
                    elif len(parts) == 2 and parts[0] == 'TCPSocket':
                        port = int(parts[1])
                        if 0 < port < 65536:
                            endpoints.insert(0, ('tcp', ('127.0.0.1', port)))
            except (OSError, ValueError, UnicodeError):
                pass
        return endpoints + super().clamd_endpoints()

    def clamd_listen_config(self, work_dir):
        path = str(work_dir / 'clamd.sock')
        return ('unix', path), [f'LocalSocket {path}', 'LocalSocketMode 600']

    # ── process management ──────────────────────────────────────────

    def start_process(self, cmd, **kwargs):
        kwargs.setdefault("preexec_fn", os.setsid)
        return subprocess.Popen(cmd, **kwargs)

    def stop_process(self, process):
        if process.poll() is None:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)

    # ── writable data directories ───────────────────────────────────

    def config_dir(self) -> Path:
        xdg_config = os.environ.get("XDG_CONFIG_HOME",
                                     os.path.join(os.path.expanduser("~"), ".config"))
        return Path(xdg_config) / APP_NAME

    def data_dir(self) -> Path:
        xdg_data = os.environ.get("XDG_DATA_HOME",
                                   os.path.join(os.path.expanduser("~"), ".local", "share"))
        return Path(xdg_data) / APP_NAME

    def db_dir(self) -> Path | None:
        """Linux does not manage its own database — ClamAV uses its
        system-wide database directory (e.g. /var/lib/clamav)."""
        return None

    def manages_own_database(self) -> bool:
        return False

    def system_db_locations(self) -> list[Path]:
        return [Path("/var/lib/clamav")]

    def log_dir(self) -> Path:
        return self.data_dir() / "logs"

    def updates_dir(self) -> Path:
        return self.data_dir() / "updates"

    def quarantine_dir(self) -> Path:
        return self.data_dir() / "quarantine"

    # ── ClamAV runtime detection ────────────────────────────────────

    def detect_clamav_runtime(self) -> RuntimeInfo:
        """Find ClamAV via system PATH."""
        cs = shutil.which("clamscan")
        fc = shutil.which("freshclam")

        if cs:
            version_raw = self.get_clamav_version(cs)
            return RuntimeInfo(
                source="system-path",
                clamscan=cs,
                freshclam=fc,
                version=version_raw,
                version_num=_parse_version(version_raw),
            )

        return RuntimeInfo(
            source="none",
            clamscan=None,
            freshclam=None,
            version=None,
            version_num=None,
        )

    def get_clamav_version(self, clamscan_path: str) -> str | None:
        try:
            result = subprocess.run(
                [clamscan_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip().split("\n")[0]
        except Exception:
            pass
        return None

    def manages_own_runtime(self) -> bool:
        return False

    def runtime_install_instructions(self) -> str:
        distro = self.distro_info()

        if distro["unknown"] == "true":
            return (
                "Could not identify your Linux distribution.\n\n"
                "Please install ClamAV using your system's package manager.\n"
                "Common package names:\n"
                "  • Debian/Ubuntu:  clamav clamav-freshclam clamav-daemon\n"
                "  • Fedora/RHEL:    clamav clamav-update clamd\n"
                "  • Arch/Manjaro:   clamav\n"
                "  • openSUSE:       clamav\n"
                "  • Gentoo:         app-antivirus/clamav\n"
                "  • Alpine:         clamav clamav-daemon\n\n"
                "After installing, use Check status in LibreWard."
            )

        lines = [
            f"Detected: {distro['name']}"
        ]
        if distro["version"]:
            lines.append(f"Version:  {distro['version']}")

        lines.extend([
            "",
            "To install ClamAV, open a terminal and run:",
            "",
            f"  {distro['install_cmd']}",
            "",
            "After installation, use Check status in LibreWard.",
            "The daemon provides optional parallel scanning. LibreWard reuses",
            "a running local daemon or starts the installed daemon when needed.",
            "",
            "Your package manager will also handle ClamAV updates.",
        ])

        return "\n".join(lines)

    # ── excludes ────────────────────────────────────────────────────

    def default_common_excludes(self) -> dict[str, list[str]]:
        return {
            "Python virtual environments (.venv, venv, env)": [
                r"(^|/)\.venv($|/)",
                r"(^|/)venv($|/)",
                r"(^|/)env($|/)",
            ],
            "Python cache dirs (__pycache__, .pytest_cache, .mypy_cache, .ruff_cache)": [
                r"(^|/)__pycache__($|/)",
                r"(^|/)\.pytest_cache($|/)",
                r"(^|/)\.mypy_cache($|/)",
                r"(^|/)\.ruff_cache($|/)",
            ],
            "Node.js dependencies/cache (node_modules, .npm)": [
                r"(^|/)node_modules($|/)",
                r"(^|/)\.npm($|/)",
            ],
            "Rust cache/build dirs (target, .cargo)": [
                r"(^|/)target($|/)",
                r"(^|/)\.cargo($|/)",
            ],
            "Git directories (.git)": [
                r"(^|/)\.git($|/)",
            ],
            "General cache dirs (.cache)": [
                r"(^|/)\.cache($|/)",
            ],
            "Podman rootless internal storage": [
                os.path.join(
                    os.path.expanduser("~"), ".local/share/containers/storage"
                ),
            ],
        }

    # ── quick scan paths ───────────────────────────────────────────

    def quick_scan_paths(self) -> list[str]:
        """Return Linux-specific quick scan paths."""
        home = os.path.expanduser("~")
        candidates = [
            # Temp / shared memory (common malware staging)
            "/tmp",
            "/var/tmp",
            "/dev/shm",
            # User-writable common locations
            os.path.join(home, "Downloads"),
            os.path.join(home, "Desktop"),
            os.path.join(home, ".cache"),
            # Perzistencija
            os.path.join(home, ".config", "autostart"),
            # Trash
            os.path.join(home, ".local", "share", "Trash"),
            # Browser caches
            os.path.join(home, ".cache", "mozilla"),
            os.path.join(home, ".config", "chromium"),
            os.path.join(home, ".config", "google-chrome"),
            os.path.join(home, ".config", "microsoft-edge"),
            os.path.join(home, ".cache", "BraveSoftware"),
            # Snap tmp area (if it exists)
            os.path.join(home, "snap"),
        ]
        return [p for p in candidates if os.path.isdir(p)]

    # ── platform info ───────────────────────────────────────────────

    def platform_arch(self) -> str:
        machine = _platform.machine().lower()
        if machine in ("x86_64", "amd64"):
            arch = "x64"
        elif machine in ("i386", "i686"):
            arch = "x86"
        elif machine in ("aarch64", "arm64"):
            arch = "arm64"
        else:
            arch = machine
        return f"linux-{arch}"

    # ── distro detection & install instructions ─────────────────────

    def distro_info(self) -> dict[str, str]:
        """Detect the Linux distribution.

        Returns a dict with keys:
          id            — short distro ID (arch, ubuntu, fedora, debian, ...)
          name          — human-readable name (Arch Linux, Ubuntu, ...)
          version       — version string if available
          pkg_manager   — primary package manager (pacman, apt, dnf, zypper, ...)
          install_cmd   — command to install ClamAV (sudo pacman -S clamav)
          update_cmd    — command to update all packages (sudo pacman -Syu)
          unknown       — "true" if detection failed
        """
        # Parse /etc/os-release (exists on most modern distros)
        os_release = self._read_os_release()

        distro_id = os_release.get("ID", "")
        id_like = os_release.get("ID_LIKE", "")
        name = os_release.get("NAME", "")
        version = os_release.get("VERSION_ID", "")

        # Map distro ID to package manager commands
        pkg_map: dict[str, dict[str, str]] = {
            "arch": {
                "pkg_manager": "pacman",
                "install_cmd": "sudo pacman -S clamav",
                "update_cmd": "sudo pacman -Syu",
            },
            "manjaro": {
                "pkg_manager": "pacman",
                "install_cmd": "sudo pacman -S clamav",
                "update_cmd": "sudo pacman -Syu",
            },
            "endeavouros": {
                "pkg_manager": "pacman",
                "install_cmd": "sudo pacman -S clamav",
                "update_cmd": "sudo pacman -Syu",
            },
            "ubuntu": {
                "pkg_manager": "apt",
                "install_cmd": "sudo apt install clamav clamav-freshclam clamav-daemon",
                "update_cmd": "sudo apt upgrade",
            },
            "debian": {
                "pkg_manager": "apt",
                "install_cmd": "sudo apt install clamav clamav-freshclam clamav-daemon",
                "update_cmd": "sudo apt upgrade",
            },
            "linuxmint": {
                "pkg_manager": "apt",
                "install_cmd": "sudo apt install clamav clamav-freshclam clamav-daemon",
                "update_cmd": "sudo apt upgrade",
            },
            "pop": {
                "pkg_manager": "apt",
                "install_cmd": "sudo apt install clamav clamav-freshclam clamav-daemon",
                "update_cmd": "sudo apt upgrade",
            },
            "fedora": {
                "pkg_manager": "dnf",
                "install_cmd": "sudo dnf install clamav clamav-update clamd",
                "update_cmd": "sudo dnf upgrade",
            },
            "rhel": {
                "pkg_manager": "dnf",
                "install_cmd": "sudo dnf install clamav clamav-update clamd",
                "update_cmd": "sudo dnf upgrade",
            },
            "centos": {
                "pkg_manager": "dnf",
                "install_cmd": "sudo dnf install clamav clamav-update clamd",
                "update_cmd": "sudo dnf upgrade",
            },
            "opensuse-tumbleweed": {
                "pkg_manager": "zypper",
                "install_cmd": "sudo zypper install clamav",
                "update_cmd": "sudo zypper update",
            },
            "opensuse-leap": {
                "pkg_manager": "zypper",
                "install_cmd": "sudo zypper install clamav",
                "update_cmd": "sudo zypper update",
            },
            "opensuse": {
                "pkg_manager": "zypper",
                "install_cmd": "sudo zypper install clamav",
                "update_cmd": "sudo zypper update",
            },
            "solus": {
                "pkg_manager": "eopkg",
                "install_cmd": "sudo eopkg install clamav",
                "update_cmd": "sudo eopkg upgrade",
            },
            "void": {
                "pkg_manager": "xbps",
                "install_cmd": "sudo xbps-install -S clamav",
                "update_cmd": "sudo xbps-install -Su",
            },
            "alpine": {
                "pkg_manager": "apk",
                "install_cmd": "sudo apk add clamav clamav-daemon",
                "update_cmd": "sudo apk upgrade",
            },
            "gentoo": {
                "pkg_manager": "emerge",
                "install_cmd": "sudo emerge --ask app-antivirus/clamav",
                "update_cmd": "sudo emerge --ask --update --deep @world",
            },
        }

        # Match by ID first, then by ID_LIKE
        info = pkg_map.get(distro_id)
        if info is None and id_like:
            for like_id in id_like.split():
                like_id = like_id.strip()
                info = pkg_map.get(like_id)
                if info:
                    break

        if info is not None:
            return {
                "id": distro_id,
                "name": name or distro_id.title(),
                "version": version,
                "pkg_manager": info["pkg_manager"],
                "install_cmd": info["install_cmd"],
                "update_cmd": info["update_cmd"],
                "unknown": "false",
            }

        # Unknown — generic fallback
        return {
            "id": distro_id or "unknown",
            "name": name or "Unknown Linux",
            "version": version,
            "pkg_manager": "",
            "install_cmd": "",
            "update_cmd": "",
            "unknown": "true",
        }

    @staticmethod
    def _read_os_release() -> dict[str, str]:
        """Parse /etc/os-release into a dict."""
        result: dict[str, str] = {}
        for path in ("/etc/os-release", "/usr/lib/os-release"):
            try:
                with open(path, encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "=" in line:
                            key, _, val = line.partition("=")
                            val = val.strip().strip('"').strip("'")
                            result[key.strip()] = val
                if "ID" in result:
                    return result
            except (OSError, IOError):
                continue
        return result

    @staticmethod
    def _firewall_executable(name):
        found = shutil.which(name)
        if found:
            return found
        for folder in ('/usr/sbin', '/sbin', '/usr/bin'):
            candidate = Path(folder) / name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        return None

    @staticmethod
    def _firewall_query(command, *, timeout=10):
        try:
            result = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8',
                errors='replace', timeout=timeout, env={**os.environ, 'LC_ALL': 'C'},
            )
            # stderr is redirected to stdout, so CompletedProcess.stderr is None.
            return result.returncode, (result.stdout or '').strip()
        except (OSError, subprocess.TimeoutExpired) as exc:
            return -1, str(exc)

    def inspect_firewall(self, *, privileged=False, tool_name=None):
        from core.firewall import FirewallSnapshot, FirewallTool
        import shlex
        tools = []
        specifications = (
            ('ufw', 'UFW', ['status', 'verbose']),
            ('firewall-cmd', 'firewalld', ['--state']),
            ('nft', 'nftables', ['list', 'ruleset']),
            ('iptables-save', 'iptables (IPv4)', []),
            ('ip6tables-save', 'iptables (IPv6)', []),
        )
        if privileged and tool_name not in {item[1] for item in specifications}:
            raise ValueError('Select a detected firewall tool first.')
        authorizer = self._trusted_firewall_executable('pkexec') if privileged else None
        if privileged and not authorizer:
            raise RuntimeError('System authorization (pkexec) is unavailable. Use the displayed sudo commands in a terminal.')

        def query(command):
            if not privileged:
                return self._firewall_query(command)
            code, output = self._firewall_query([authorizer, '--disable-internal-agent', *command], timeout=120)
            if code in (126, 127):
                raise RuntimeError('Firewall authorization was cancelled or could not be obtained. Existing rules were not changed.')
            return code, output

        for executable, name, arguments in specifications:
            if tool_name is not None and name != tool_name:
                continue
            path = (self._trusted_firewall_executable(executable) if privileged else
                    self._firewall_executable(executable))
            if not path:
                continue
            if privileged and executable == 'firewall-cmd':
                arguments = ['--list-all-zones']
            command = [path, *arguments]
            code, output = query(command)
            lowered = output.lower()
            denied = any(word in lowered for word in (
                'permission denied', 'operation not permitted', 'must be root',
                'need to be root', 'access denied', 'not authorized', 'authorization failed'))
            state = 'Unknown — administrator permission required' if denied else 'Unknown — query failed'
            if code == 0:
                if executable == 'ufw':
                    state = 'Inactive' if 'status: inactive' in lowered else (
                        'Active' if 'status: active' in lowered else 'Unknown')
                elif executable == 'firewall-cmd':
                    state = 'Running' if privileged or output.strip() == 'running' else 'Unknown'
                else:
                    state = 'Rules present' if output.strip() else 'No rules returned'
            elif executable == 'firewall-cmd' and 'not running' in lowered:
                state = 'Not running'
            sections = [output or 'No output returned.']
            extra = []
            if executable == 'ufw':
                extra = [('Configured UFW rules (may be inactive)', ['show', 'added'])]
            elif executable == 'firewall-cmd' and state == 'Running':
                extra = [('Runtime zones and rules', ['--list-all-zones']),
                         ('Permanent zones and rules (may differ from runtime)', ['--permanent', '--list-all-zones'])]
            if privileged:
                extra = []  # One authorization and one read query per button click.
                if executable == 'ufw':
                    sections.append('This view shows current status and active rules. Initial automatic detection also checks configured rules.')
                elif executable == 'firewall-cmd':
                    sections.insert(0, 'Runtime zones and rules (permanent configuration is not queried in this authorized view).')
            for heading, args in extra:
                _, details = query([path, *args])
                sections.append(heading + '\n' + (details or 'No output returned.'))
            manual = ['sudo ' + shlex.join(command)]
            manual.extend('sudo ' + shlex.join([path, *args]) for _, args in extra)
            tools.append(FirewallTool(name, state, '\n\n'.join(sections), '\n'.join(manual)))
        if privileged and not tools:
            raise RuntimeError('The selected firewall tool is no longer available in a trusted system location.')
        instructions = (
            'Installed tools can share the same Linux firewall. Installation alone does not mean protection is active. '
            'Reading rules does not change network access. Enable firewall and Add rule require explicit confirmation and system authorization. '
            'Use Read as administrator for the selected tool, or run the displayed read commands in a terminal.'
        )
        if not tools:
            manager = self.distro_info().get('pkg_manager')
            install = {'apt': 'sudo apt install ufw', 'pacman': 'sudo pacman -S ufw',
                       'apk': 'sudo apk add ufw'}.get(manager)
            instructions = (
                'No supported firewall command was found. This does not prove the system has no firewall rules. '
                'Recommended for a simple desktop setup: UFW.\n\n'
                + (f'Install using your distribution package manager:\n{install}\n\n' if install else
                   'Check your distribution documentation for the UFW package and installation instructions.\n\n')
                + 'After installation, use Read as administrator to detect the newly installed tool. Installing UFW does not enable it. '
                'Review required incoming connections before enabling it, especially on a remote computer.\n'
                'UFW documentation: https://help.ubuntu.com/community/UFW'
            )
        return FirewallSnapshot(True, tools, instructions)

    @staticmethod
    def _trusted_firewall_executable(name):
        """Elevated commands must never come from user-controlled PATH entries."""
        import stat
        for folder in ('/usr/sbin', '/usr/bin', '/sbin', '/bin'):
            path = Path(folder, name).resolve()
            try:
                chain = [path, *path.parents]
                if not path.is_file() or not os.access(path, os.X_OK):
                    continue
                if all(item.stat().st_uid == 0 and not
                       (item.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)) for item in chain):
                    return str(path)
            except OSError:
                continue
        return None

    @staticmethod
    def _firewall_change_arguments(tool_name, rule=None, *, enabled=True):
        """Allowlisted commands only. No caller-supplied executable or shell text."""
        if tool_name not in ('UFW', 'firewalld'):
            raise ValueError('Rule management is available for UFW and firewalld only.')
        if rule is None:
            if not isinstance(enabled, bool):
                raise ValueError('Firewall state must be enabled or disabled.')
            return ('ufw', ['--force', 'enable' if enabled else 'disable']) if tool_name == 'UFW' else (
                'systemctl', ['start' if enabled else 'stop', 'firewalld.service'])
        from core.firewall import FirewallRule
        if not isinstance(rule, FirewallRule):
            raise ValueError('A structured firewall rule is required.')
        rule = rule.validated()
        if rule.direction == 'both':
            raise ValueError('Both directions must be expanded into separate rules.')
        if tool_name == 'UFW':
            peer = rule.subnet if rule.scope == 'lan' else 'any'
            source, destination = (peer, 'any') if rule.direction == 'in' else ('any', peer)
            return 'ufw', [rule.action, rule.direction, 'proto', rule.protocol,
                           'from', source, 'to', destination, 'port', rule.port.replace('-', ':')]
        if rule.direction != 'in':
            raise ValueError('This firewalld form supports incoming rules only. Outgoing rules require firewalld policies.')
        if not rule.zone:
            raise ValueError('Select the firewalld zone that handles the connection.')
        source = ''
        family = ''
        if rule.scope == 'lan':
            import ipaddress
            family = f' family="ipv{ipaddress.ip_network(rule.subnet).version}"'
            source = f' source address="{rule.subnet}"'
        verdict = 'accept' if rule.action == 'allow' else 'drop'
        rich_rule = f'rule{family}{source} port port="{rule.port}" protocol="{rule.protocol}" {verdict}'
        args = [f'--zone={rule.zone}']
        if rule.lifetime == 'permanent':
            args.append('--permanent')
        args.append('--add-rich-rule=' + rich_rule)
        return 'firewall-cmd', args

    def _firewall_change_commands(self, tool_name, *, rule=None, enabled=True):
        from dataclasses import replace
        from core.firewall import FirewallRule
        if isinstance(rule, FirewallRule) and rule.direction == 'both':
            rule = rule.validated()
            # Two distinct directional rules; LAN matches the peer in each direction.
            return [self._firewall_change_arguments(tool_name, replace(rule, direction=direction))
                    for direction in ('in', 'out')]
        return [self._firewall_change_arguments(tool_name, rule, enabled=enabled)]

    def firewall_change_preview(self, tool_name, *, rule=None, enabled=True):
        import shlex
        return '\n'.join(shlex.join([executable, *args]) for executable, args in
                         self._firewall_change_commands(tool_name, rule=rule, enabled=enabled))

    def change_firewall(self, tool_name, *, rule=None, enabled=True):
        """One authorization for a validated change batch and verified refresh."""
        import shlex
        import uuid
        from core.firewall import FirewallChangeResult, FirewallSnapshot, FirewallTool
        commands = self._firewall_change_commands(tool_name, rule=rule, enabled=enabled)
        authorizer = self._trusted_firewall_executable('pkexec')
        shell = self._trusted_firewall_executable('sh')
        resolved = []
        for executable, args in commands:
            path = self._trusted_firewall_executable(executable)
            if not path:
                raise RuntimeError('The firewall command is unavailable in a trusted system location.')
            resolved.append([path, *args])
        reader = self._trusted_firewall_executable('ufw' if tool_name == 'UFW' else 'firewall-cmd')
        if not authorizer or not shell or not reader:
            raise RuntimeError('System authorization or firewall commands are unavailable in trusted system locations.')
        if rule is None and enabled:
            other = 'firewall-cmd' if tool_name == 'UFW' else 'ufw'
            other_path = self._firewall_executable(other)
            if other_path:
                code, output = self._firewall_query([other_path, '--state'] if other == 'firewall-cmd' else [other_path, 'status'])
                active = code == 0 and (output.strip() == 'running' if other == 'firewall-cmd' else 'status: active' in output.lower())
                inactive = 'not running' in output.lower() if other == 'firewall-cmd' else code == 0 and 'status: inactive' in output.lower()
                if active or not inactive:
                    raise RuntimeError('Another firewall manager is active or its state could not be verified. Keep only one manager active.')
        read_command = [reader, 'status', 'verbose'] if tool_name == 'UFW' else [reader, '--list-all-zones']
        marker = 'LIBREWARD_' + uuid.uuid4().hex
        # All commands are generated from validated fields and individually shell-quoted.
        # No caller-supplied script, executable, option or shell fragment is accepted.
        script = ('LC_ALL=C; export LC_ALL; ' + ' && '.join(shlex.join(command) for command in resolved)
                  + '; change_status=$?; printf "\n' + marker + ':CHANGE:%s\n" "$change_status"; '
                  + shlex.join(read_command)
                  + '; read_status=$?; printf "\n' + marker + ':READ:%s\n" "$read_status"')
        code, output = self._firewall_query([authorizer, '--disable-internal-agent', shell, '-c', script], timeout=120)
        if code in (126, 127):
            raise RuntimeError('Firewall authorization was cancelled or could not be obtained. No success was confirmed.')
        change_match = re.search(r'(?:^|\n)' + marker + r':CHANGE:([0-9]+)\n', output)
        read_match = re.search(r'(?:^|\n)' + marker + r':READ:([0-9]+)(?:\n|$)', output)
        if code != 0 or not change_match or not read_match:
            raise RuntimeError('The operation could not be verified. Refresh current status and rules before retrying.')
        message = output[:change_match.start()].strip()
        rules = output[change_match.end():read_match.start()].strip()
        success = change_match.group(1) == '0'
        read_code = int(read_match.group(1))
        if tool_name == 'UFW':
            state = ('Inactive' if 'status: inactive' in rules.lower() else 'Active' if 'status: active' in rules.lower() else 'Unknown') if read_code == 0 else 'Unknown'
        else:
            state = 'Running' if read_code == 0 else 'Not running' if 'not running' in rules.lower() else 'Unknown'
        refresh_error = '' if state != 'Unknown' else 'Status refresh could not be verified. Read current rules before retrying.'
        tool = FirewallTool(tool_name, state, rules or 'No rules returned.', 'sudo ' + shlex.join(read_command))
        snapshot = FirewallSnapshot(True, [tool], 'Status and rules refreshed automatically after the operation.')
        if not success:
            message = 'The change did not fully complete. Some rules may have been applied; inspect the refreshed rules before retrying.\n' + message
        return FirewallChangeResult(success, message or 'Change completed.', snapshot, refresh_error)

    def firewall_networks(self):
        import ipaddress
        import json
        path = self._firewall_executable('ip')
        if not path:
            return []
        code, output = self._firewall_query([path, '-j', 'address', 'show', 'up'], timeout=3)
        if code != 0:
            return []
        try:
            interfaces = json.loads(output)
            if not isinstance(interfaces, list):
                return []
            networks = []
            for interface in interfaces:
                if not isinstance(interface, dict):
                    continue
                if interface.get('ifname') == 'lo' or 'LOOPBACK' in interface.get('flags', []):
                    continue
                for address in interface.get('addr_info', []):
                    if address.get('family') not in ('inet', 'inet6'):
                        continue
                    network = ipaddress.ip_network(f"{address['local']}/{address['prefixlen']}", strict=False)
                    if network.prefixlen == 0 or network.is_loopback or network.is_link_local or network.is_multicast:
                        continue
                    entry = (str(interface['ifname']), str(network))
                    if entry not in networks:
                        networks.append(entry)
            return networks
        except (ValueError, KeyError, TypeError):
            return []
