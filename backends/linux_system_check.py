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


# ── deeper checks with administrator rights (run as root through pkexec) ──
#
# This module uses only the standard library: its source is passed to a trusted
# /usr/bin/python3 -I, so root never imports files from the application folder.

PROGRAM_FOLDERS = ('/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/', '/usr/lib/', '/usr/lib64/', '/usr/libexec/',
                   '/lib/', '/lib64/', '/usr/local/bin/', '/usr/local/sbin/')
LOCAL_FILESYSTEMS = {'ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'f2fs', 'jfs', 'reiserfs', 'zfs', 'bcachefs'}
SKIPPED_MOUNTS = ('/proc', '/sys', '/dev', '/run', '/snap', '/var/lib/snapd', '/var/lib/docker',
                  '/var/lib/containers', '/tmp/.mount_')
# /usr merge: Debian's package database may list /bin/x for /usr/bin/x.
MERGED = (('/usr/bin/', '/bin/'), ('/usr/sbin/', '/sbin/'), ('/usr/lib/', '/lib/'), ('/usr/lib64/', '/lib64/'))


def _run(command, timeout):
    result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace',
                            timeout=timeout, stdin=subprocess.DEVNULL, check=False)
    return result.stdout + result.stderr


def changed_package_files(manager, output):
    """Programs and libraries whose contents differ from their package, from verify output."""
    changed = []
    for line in output.splitlines():
        if manager == 'pacman':
            match = re.match(r'warning: (\S+): (/.+) \((SHA256|MD5) checksum mismatch\)$', line.strip())
            path = match.group(2) if match else None
        else:
            # rpm -Va / dpkg --verify: 9 flags ("5" third: contents differ), a type
            # ("c" for configuration), then the path.
            match = re.match(r'^([.?SM5DLUGTP]{9})\s+([cdglr]?)\s*(/.+)$', line.rstrip())
            path = match.group(3) if match and match.group(1)[2] == '5' and match.group(2) != 'c' else None
        if path and path.startswith(PROGRAM_FOLDERS):
            changed.append(path)
    return list(dict.fromkeys(changed))


def verify_packages(manager, tool):
    command = {'rpm': [tool, '-Va', '--nodeps', '--noscripts'], 'dpkg': [tool, '--verify'],
               'pacman': [tool, '-Qkk']}[manager]
    return changed_package_files(manager, _run(command, 3600))


def merged_aliases(path):
    """The same file under the other name of a merged /usr: /usr/bin/x and /bin/x."""
    return [second + path[len(first):] for one, other in MERGED
            for first, second in ((one, other), (other, one)) if path.startswith(first)]


def unowned_files(manager, tool, paths):
    """Paths that belong to no installed package."""
    if not paths:
        return []
    queries = list(paths)
    if manager == 'dpkg':
        queries += [alias for path in paths for alias in merged_aliases(path)]
    command = {'rpm': [tool, '-qf', '--', *queries], 'dpkg': [tool, '-S', '--', *queries],
               'pacman': [tool, '-Qo', '--', *queries]}[manager]
    output = _run(command, 600)
    messages = {'rpm': 'file {} is not owned by any package', 'dpkg': 'no path found matching pattern {}',
                'pacman': 'No package owns {}'}[manager]
    missing = {query for query in queries if messages.format(query) in output}
    unowned = []
    for path in paths:
        aliases = [path] + (merged_aliases(path) if manager == 'dpkg' else [])
        if all(alias in missing for alias in aliases):
            unowned.append(path)
    return unowned


def local_mounts(mounts='/proc/self/mounts'):
    points = []
    for line in (_read(mounts) or '').splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[2] not in LOCAL_FILESYSTEMS:
            continue
        point = parts[1].replace('\\040', ' ')
        # Single files bind-mounted into place are not folders to search.
        if not point.startswith(SKIPPED_MOUNTS) and os.path.isdir(point):
            points.append(point)
    return sorted(set(points))


def special_permission_programs(find, mounts):
    """Programs that run with their owner's rights (SUID/SGID), on local filesystems."""
    files = []
    for point in mounts:
        output = _run([find, point, '-xdev', '-type', 'f', '-perm', '/6000', '-print'], 1800)
        files += [line for line in output.splitlines() if line.startswith('/')]
    return sorted(set(files))


def unit_programs(folders):
    """(unit file, program) of the ExecStart lines of system services in `folders`."""
    import shlex
    programs = []
    for folder in folders:
        try:
            units = sorted(Path(folder).glob('*.service'))
        except OSError:
            continue
        for unit in units:
            if unit.is_symlink() or not unit.is_file():
                continue  # enabled through a link to a unit elsewhere
            for line in _settings(_read(unit)):
                key, _equals, command = line.partition('=')
                if not key.strip().startswith('Exec') or not command.strip():
                    continue
                try:
                    program = shlex.split(command)[0].lstrip('@-:+!|')
                except (ValueError, IndexError):
                    continue
                if os.path.isabs(program):
                    programs.append((str(unit), program))
    return programs


def all_crontab_commands(spool=('/var/spool/cron', '/var/spool/cron/crontabs'), etc='/etc'):
    commands = []
    for folder in spool:
        try:
            files = sorted(path for path in Path(folder).iterdir() if path.is_file())
        except OSError:
            continue
        commands += [(f'crontab of {path.name}', line) for path in files for line in _settings(_read(path))]
    for period in ('hourly', 'daily', 'weekly', 'monthly'):
        folder = Path(etc) / f'cron.{period}'
        if folder.is_dir():
            commands += [(str(path), line) for path in sorted(folder.iterdir()) if path.is_file()
                         for line in _settings(_read(path))]
    return commands + crontab_commands(etc, crontab='')


def run_root_checks(manager, tools, *, proc='/proc', sys='/sys', etc='/etc', mounts='/proc/self/mounts',
                    unit_folders=('/etc/systemd/system', '/usr/local/lib/systemd/system'),
                    package_unit_folders=('/usr/lib/systemd/system', '/lib/systemd/system'),
                    spool=('/var/spool/cron', '/var/spool/cron/crontabs')):
    """Checks that need root: (findings, names of the checks that ran).

    manager: 'rpm', 'dpkg', 'pacman' or None; tools: trusted paths of the
    manager's command and of find.
    """
    tool = tools.get(manager)
    checks = [
        ('Extra libraries forced into every program', lambda: preload_file(etc)),
        ('Programs of all users running from temporary folders or only from memory',
         lambda: suspicious_processes(proc)),
        ('Hidden programs of all users', lambda: hidden_processes(proc)),
        ('Hidden kernel modules', lambda: hidden_modules(proc, sys)),
        ('Scheduled tasks of all users', lambda: suspicious_startup_commands(all_crontab_commands(spool, etc))),
    ]
    if tool:
        checks += [
            ('System programs and libraries compared with their packages', lambda: [
                finding('changed-program', 'A system program was changed',
                        f'{path} differs from the copy its package installed. Rootkits replace programs such as '
                        'ps, ls or sshd to hide; reinstalling the package restores the original.', path)
                for path in verify_packages(manager, tool)]),
            ('Programs with special rights (SUID/SGID)', lambda: [
                finding('special-rights', 'A program with administrator rights was not installed by a package',
                        f'{path} runs with the rights of its owner but belongs to no installed package. '
                        'Attackers leave such programs to become administrator again later.', path)
                for path in unowned_files(manager, tool, special_permission_programs(tools['find'], local_mounts(mounts)))]
             if tools.get('find') else []),
            ('System services', lambda: system_service_findings(manager, tool, unit_folders, package_unit_folders)),
        ]
    findings, ran = [], []
    for name, check in checks:
        try:
            findings += check()
            ran.append(name)
        except (OSError, subprocess.TimeoutExpired):
            continue
    return findings, ran


def system_service_findings(manager, tool, unit_folders, package_unit_folders):
    findings = []
    package_units = []
    # With a merged /usr, /lib/systemd/system is the same folder as /usr/lib/systemd/system.
    package_unit_folders = list({os.path.realpath(folder): folder for folder in package_unit_folders}.values())
    for folder in package_unit_folders:
        try:
            package_units += [str(path) for path in sorted(Path(folder).glob('*.service'))
                              if path.is_file() and not path.is_symlink()]
        except OSError:
            continue
    for unit in unowned_files(manager, tool, package_units):
        findings.append(finding('unowned-service', 'A system service was not installed by a package',
                                f'{unit} is in the folder of installed packages but belongs to none.', unit))
    programs = unit_programs(list(unit_folders) + list(package_unit_folders))
    unowned = set(unowned_files(manager, tool, sorted({program for _unit, program in programs
                                                        if os.path.isfile(program)})))
    for unit, program in programs:
        if program.startswith(TEMPORARY) or program.startswith('/home/'):
            findings.append(finding('service-program', 'A system service runs a program from an unusual folder',
                                    f'{unit} runs {program} as a system service.', unit))
        elif program in unowned:
            findings.append(finding('service-program', 'A system service runs a program not installed by a package',
                                    f'{unit} runs {program}, which belongs to no installed package. This is normal '
                                    'for software installed by hand, and unusual otherwise.', unit))
    return findings


def root_main(arguments):
    """Entry point of the helper that pkexec runs: JSON settings in, JSON result out."""
    import json
    settings = json.loads(arguments[0])
    findings, ran = run_root_checks(settings.get('manager'), settings.get('tools', {}))
    print(json.dumps({'findings': findings, 'checks': ran}))
