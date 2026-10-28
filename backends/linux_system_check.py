"""Signs of a hidden intruder that a normal user can see, without root.

Each check looks for something a normal desktop does not do: an extra library
forced into every program, programs running from temporary folders or only from
memory, processes or kernel modules hidden from their lists, and startup entries
that download or decode commands and run them. The checks report findings; they
never change anything. Paths are parameters so tests can use a fake /proc.
"""
import os
import re
import shutil
import subprocess
from pathlib import Path

TEMPORARY = ('/tmp/', '/var/tmp/', '/dev/shm/')
# AppImages run from a folder they mount or unpack in /tmp.
APPIMAGE = ('/tmp/.mount_', '/tmp/appimage_extracted_')
# Container runtimes run a copy of themselves from memory on purpose.
MEMORY_ALLOWED = ('memfd:runc',)
# Linux PIDs never exceed this (PID_MAX_LIMIT on 64-bit systems).
PID_LIMIT = 4194304

RUNS_FROM_TEMPORARY = re.compile(r'(^|[\s"\'=:;|&(])(/tmp|/var/tmp|/dev/shm)/(?!\.mount_)')
DOWNLOADS_AND_RUNS = re.compile(r'\b(curl|wget)\b[^;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b')
DECODES_AND_RUNS = re.compile(r'\bbase64\s+(-d|--decode)\b[^;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b')

STARTUP_FILES = ('.profile', '.bash_profile', '.bash_login', '.bashrc', '.zshenv', '.zprofile', '.zshrc',
                 '.xprofile', '.xsessionrc', '.pam_environment')


def finding(check, title, detail, where=''):
    return {'check': check, 'title': title, 'detail': detail, 'where': where}


def _read(path):
    try:
        return Path(path).read_text(encoding='utf-8', errors='replace')
    except OSError:
        return None


def _settings(text):
    """Lines that are not empty and not comments."""
    return [line.strip() for line in (text or '').splitlines() if line.strip() and not line.strip().startswith('#')]


def _process_name(proc, pid):
    """The name the program was started with; comm is "3" for a program run from /proc/self/fd/3."""
    try:
        command = (Path(proc) / str(pid) / 'cmdline').read_bytes().split(b'\0')[0]
    except OSError:
        command = b''
    name = os.path.basename(command.decode('utf-8', errors='replace'))
    return name or (_read(Path(proc) / str(pid) / 'comm') or '').strip() or 'unknown'


def listed_pids(proc):
    return {int(name) for name in os.listdir(proc) if name.isdigit()}


# ── checks ─────────────────────────────────────────────────────────

def preload_file(etc='/etc'):
    libraries = _settings(_read(Path(etc) / 'ld.so.preload'))
    if not libraries:
        return []
    return [finding('preload', 'Every program is made to load an extra library',
                    f"{Path(etc) / 'ld.so.preload'} makes every program on this computer load "
                    f"{', '.join(libraries)}. Some rootkits hide this way; normal systems do not use this file.",
                    str(Path(etc) / 'ld.so.preload'))]


def preload_in_startup_files(home, config, etc='/etc'):
    home, config = Path(home), Path(config)
    files = [home / name for name in STARTUP_FILES]
    files += sorted((config / 'environment.d').glob('*.conf')) if (config / 'environment.d').is_dir() else []
    files += sorted((config / 'systemd' / 'user').rglob('*')) if (config / 'systemd' / 'user').is_dir() else []
    files += [Path(etc) / 'environment']
    files += sorted((Path(etc) / 'profile.d').glob('*')) if (Path(etc) / 'profile.d').is_dir() else []
    findings = []
    for path in files:
        if not path.is_file():
            continue
        lines = [line for line in _settings(_read(path)) if re.search(r'\bLD_PRELOAD\s*=', line)]
        if lines:
            findings.append(finding('preload-startup', 'A startup file makes programs load an extra library',
                                    f'{path} sets LD_PRELOAD: {lines[0]}. Some rootkits hide this way; '
                                    'a few programs use it on purpose.', str(path)))
    return findings


def suspicious_processes(proc='/proc'):
    """Programs of this user running from temporary folders or only from memory."""
    findings = []
    for pid in sorted(listed_pids(proc)):
        try:
            target = os.readlink(Path(proc) / str(pid) / 'exe')
        except OSError:
            continue  # another user's process, a kernel thread, or ended meanwhile
        name = _process_name(proc, pid)
        # A program run from memory shows as "/memfd:name (deleted)".
        path = target.removesuffix(' (deleted)')
        if path.lstrip('/').startswith('memfd:'):
            if not path.lstrip('/').startswith(MEMORY_ALLOWED):
                findings.append(finding('memory-process', 'A program is running only in memory',
                                        f'{name} (process {pid}) has no program file on disk. Some attack tools '
                                        'work this way so that virus scans cannot find them.', f'process {pid}'))
        elif path.startswith(TEMPORARY) and not path.startswith(APPIMAGE):
            findings.append(finding('temporary-process', 'A program is running from a temporary folder',
                                    f'{name} (process {pid}) runs {path}. Programs are rarely started from there; '
                                    'downloaded attack tools often are.', path))
    return findings


def hidden_processes(proc='/proc', listed=listed_pids):
    """Processes that exist but are left out of /proc's listing, as rootkits do.

    Threads also exist without being listed; their thread group id differs from
    their id. Processes that started or ended meanwhile are checked again.
    """
    proc = Path(proc)
    before = listed(proc)
    try:
        last = int((_read(proc / 'sys' / 'kernel' / 'ns_last_pid') or '0').strip())
    except ValueError:
        last = 0
    top = min(max([last, *before]), PID_LIMIT)
    candidates = [pid for pid in range(1, top + 1) if pid not in before and (proc / str(pid)).exists()]
    if not candidates:
        return []
    after = listed(proc)
    findings = []
    for pid in candidates:
        if pid in after:
            continue
        status = _read(proc / str(pid) / 'status') or ''
        group = re.search(r'^Tgid:\s*(\d+)', status, re.MULTILINE)
        if group is None or int(group.group(1)) != pid:
            continue  # a thread, or it ended
        findings.append(finding('hidden-process', 'A running program is hidden',
                                f'Process {pid} ({_process_name(proc, pid)}) is running but hidden from the list of '
                                'programs. Hiding programs is what rootkits do.', f'process {pid}'))
    return findings


def hidden_modules(proc='/proc', sys='/sys'):
    """Kernel modules that are loaded but missing from /proc/modules."""
    def loaded():
        return {line.split()[0] for line in (_read(Path(proc) / 'modules') or '').splitlines() if line.strip()}

    before = loaded()
    try:
        modules = sorted((Path(sys) / 'module').iterdir())
    except OSError:
        return []
    # Built-in parts of the kernel appear in /sys/module without an initstate.
    live = [module.name for module in modules
            if module.name not in before and (_read(module / 'initstate') or '').strip() == 'live']
    after = loaded() if live else before
    return [finding('hidden-module', 'A part of the system core is hidden',
                    f'The kernel module {name} is loaded but hidden from the list of modules. '
                    'Hiding modules is what kernel rootkits do.', name)
            for name in live if name not in after]


def crontab_commands(etc='/etc', crontab=None):
    """(source, command) of this user's crontab and the readable system crontabs."""
    commands = []
    crontab = crontab if crontab is not None else shutil.which('crontab')
    if crontab:
        try:
            result = subprocess.run([crontab, '-l'], capture_output=True, text=True, timeout=10,
                                    stdin=subprocess.DEVNULL, check=False)
            if result.returncode == 0:
                commands += [('your crontab', line) for line in _settings(result.stdout)]
        except (OSError, subprocess.TimeoutExpired):
            pass
    files = [Path(etc) / 'crontab']
    files += sorted((Path(etc) / 'cron.d').glob('*')) if (Path(etc) / 'cron.d').is_dir() else []
    for path in files:
        commands += [(str(path), line) for line in _settings(_read(path))]
    return commands


def suspicious_startup_commands(commands):
    """commands: (source, command) of things that start by themselves."""
    findings = []
    for source, command in commands:
        if DOWNLOADS_AND_RUNS.search(command):
            title = 'Something that starts by itself downloads and runs a script'
        elif DECODES_AND_RUNS.search(command):
            title = 'Something that starts by itself runs hidden (encoded) commands'
        elif RUNS_FROM_TEMPORARY.search(command):
            title = 'Something that starts by itself runs a program from a temporary folder'
        else:
            continue
        findings.append(finding('startup-command', title, f'{source}: {command.strip()}', source))
    return findings


def run_checks(*, home, config, startup_commands, proc='/proc', sys='/sys', etc='/etc'):
    """All checks; (findings, names of the checks that ran)."""
    checks = [
        ('Extra libraries forced into every program', lambda: preload_file(etc)),
        ('Extra libraries set in startup files', lambda: preload_in_startup_files(home, config, etc)),
        ('Programs running from temporary folders or only from memory', lambda: suspicious_processes(proc)),
        ('Hidden programs', lambda: hidden_processes(proc)),
        ('Hidden kernel modules', lambda: hidden_modules(proc, sys)),
        ('Programs that start by themselves (autostart, systemd, cron)',
         lambda: suspicious_startup_commands(startup_commands + crontab_commands(etc))),
    ]
    findings, ran = [], []
    for name, check in checks:
        try:
            findings += check()
            ran.append(name)
        except OSError:
            continue  # unavailable here, for example /proc in a container
    return findings, ran
