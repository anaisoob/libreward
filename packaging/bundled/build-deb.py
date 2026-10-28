#!/usr/bin/env python3
"""Build a LibreWard .deb that carries its own PySide6 and watchdog.

For Ubuntu 22.04 and 24.04, Linux Mint 21 and 22, and Debian 12, which have no
PySide6 packages (or too old ones). The wheels are the ones pinned in uv.lock,
downloaded from their recorded URLs and checked against their SHA256 hashes;
PySide6 wheels are abi3, so they work with the system's Python 3.10 or newer.

    python3 packaging/bundled/build-deb.py [--arch amd64|arm64] [--output dist]

Needs Python 3.11+, make and dpkg-deb; no root, no debhelper and no pip.
"""
import argparse
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import tomllib
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WHEELS = ('pyside6-essentials', 'shiboken6', 'watchdog')
MACHINES = {'amd64': 'x86_64', 'arm64': 'aarch64'}
# Qt's own libraries are in the wheel; these come from the system.
QT_LIBRARIES = ('libc6 (>= 2.34)', 'libgl1', 'libegl1', 'libfontconfig1', 'libfreetype6', 'libxkbcommon0',
                'libxkbcommon-x11-0', 'libxcb-cursor0', 'libxcb-icccm4', 'libxcb-image0', 'libxcb-keysyms1',
                'libxcb-util1',
                'libxcb-randr0', 'libxcb-render-util0', 'libxcb-shape0', 'libxcb-xkb1', 'libx11-xcb1',
                'libdbus-1-3', 'libwayland-client0', 'libwayland-cursor0', 'libwayland-egl1',
                'libglib2.0-0t64 | libglib2.0-0')
# Qt developer tools and headers in the wheel; LibreWard runs none of them.
UNUSED = ('include', 'typesystems', 'glue', 'scripts', 'doc', 'examples', 'assistant', 'designer', 'linguist',
          'lrelease', 'lupdate', 'qmlformat', 'qmllint', 'qmlls', 'qsb', 'balsam', 'balsamui', 'rcc', 'uic',
          'svgtoqml', 'androiddeployqt', 'android_deploy', 'deploy', 'metaobjectdump', 'project',
          'qtpy2cpp', 'Qt/libexec', 'Qt/qml', 'Qt/plugins/qmltooling', 'Qt/plugins/designer',
          'Qt/plugins/qmllint', 'Qt/plugins/qmlls', 'Qt/plugins/sqldrivers')
# LibreWard imports only these Qt modules (see ui/); Qt Quick, QML and Designer
# make up most of the wheel.
QT_MODULES = {'QtCore', 'QtGui', 'QtWidgets', 'QtNetwork'}
UNUSED_LIBRARIES = re.compile(r'^libQt6(Qml|Quick|Designer|Help|Sql|Test|ShaderTools)')
# What LibreWard needs from the wheel; the build fails if pruning removed one.
REQUIRED = ('QtCore.abi3.so', 'QtGui.abi3.so', 'QtWidgets.abi3.so', 'QtNetwork.abi3.so',
            'Qt/plugins/platforms/libqxcb.so', 'Qt/plugins/platforms/libqwayland.so',
            'Qt/plugins/platforms/libqoffscreen.so', 'Qt/plugins/imageformats/libqsvg.so')


def package_version():
    changelog = (ROOT / 'packaging/debian/changelog').read_text(encoding='utf-8')
    return re.match(r'libreward \(([^)]+)\)', changelog).group(1)


def pinned_wheels(machine):
    """(file name, url, sha256) of the wheels in uv.lock for this machine."""
    lock = tomllib.loads((ROOT / 'uv.lock').read_text(encoding='utf-8'))
    wheels = []
    for name in WHEELS:
        package = next(entry for entry in lock['package'] if entry['name'] == name)
        candidates = [wheel for wheel in package.get('wheels', [])
                      if 'manylinux' in wheel['url'] and wheel['url'].endswith(f'{machine}.whl')]
        if not candidates:
            raise SystemExit(f'uv.lock has no {machine} Linux wheel of {name} {package["version"]}.')
        wheel = candidates[0]
        wheels.append((wheel['url'].rsplit('/', 1)[1], wheel['url'], wheel['hash'].removeprefix('sha256:')))
    return wheels


def download(wheels, cache):
    cache.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, url, digest in wheels:
        path = cache / name
        if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            print(f'Downloading {name}…')
            with urllib.request.urlopen(url, timeout=120) as response, open(path.with_suffix('.part'), 'wb') as out:
                shutil.copyfileobj(response, out)
            path.with_suffix('.part').replace(path)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            path.unlink()
            raise SystemExit(f'{name} does not match the SHA256 hash in uv.lock.')
        paths.append(path)
    return paths


def vendor(wheels, target):
    target.mkdir(parents=True)
    for wheel in wheels:
        with zipfile.ZipFile(wheel) as archive:
            for member in archive.infolist():
                destination = (target / member.filename).resolve()
                if not destination.is_relative_to(target.resolve()):
                    raise SystemExit(f'Unsafe path in {wheel.name}: {member.filename}')
                archive.extract(member, target)
                if member.external_attr >> 16 & 0o111:
                    destination.chmod(0o755)
    for name in UNUSED:
        path = target / 'PySide6' / name
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()
    for module in (target / 'PySide6').glob('Qt*.abi3.so'):
        if module.name.split('.')[0] not in QT_MODULES:
            module.unlink()
            module.with_name(module.name.split('.')[0] + '.pyi').unlink(missing_ok=True)
    for library in (target / 'PySide6' / 'Qt' / 'lib').iterdir():
        if UNUSED_LIBRARIES.match(library.name):
            library.unlink()
    remove_unloadable(target / 'PySide6')
    missing = [name for name in REQUIRED if not (target / 'PySide6' / name).exists()]
    if missing:
        raise SystemExit(f'Pruning removed parts LibreWard needs: {", ".join(missing)}')


def remove_unloadable(pyside):
    """Drop libraries and plugins that need a removed Qt part: nothing can load them.

    Repeated until nothing changes, as removing one can strand another. ldd cannot
    read other architectures; their unloadable files then simply stay.
    """
    environment = dict(os.environ, LD_LIBRARY_PATH=str(pyside / 'Qt' / 'lib'))
    changed = True
    while changed:
        changed = False
        for path in sorted(path for path in pyside.rglob('*.so*') if path.is_file()):
            result = subprocess.run(['ldd', str(path)], capture_output=True, text=True, env=environment, check=False)
            if re.search(r'lib(Qt6|pyside6)\S* => not found', result.stdout):
                path.unlink()
                changed = True


def control(version, arch, size):
    depends = ', '.join(('python3 (>= 3.10)', 'pkexec | policykit-1', 'systemd') + QT_LIBRARIES)
    return (f'Package: libreward\nVersion: {version}\nArchitecture: {arch}\n'
            'Maintainer: anaisoob <anaisoob@tutamail.com>\nSection: admin\nPriority: optional\n'
            f'Installed-Size: {size}\nDepends: {depends}\n'
            'Recommends: clamav, libnotify-bin, network-manager, dnsmasq-base\nSuggests: ufw\n'
            'Homepage: https://github.com/anaisoob/libreward\n'
            'Description: simple virus scanning, firewall and Internet protection\n'
            ' LibreWard is a cross-platform security and privacy desktop application. On\n'
            ' Linux it scans files with ClamAV, manages UFW or firewalld, and blocks\n'
            ' unwanted website domains with a local DNS filter in front of NetworkManager\n'
            ' or systemd-resolved.\n'
            ' .\n'
            ' This package includes PySide6 (Qt for Python, LGPLv3) and watchdog for\n'
            ' systems that do not package them.\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--arch', choices=sorted(MACHINES), default='amd64')
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    arguments = parser.parse_args()
    version = package_version()
    output = arguments.output.resolve()
    wheels = download(pinned_wheels(MACHINES[arguments.arch]), output / 'wheels')
    with tempfile.TemporaryDirectory(prefix='libreward-deb-') as directory:
        stage = Path(directory) / 'root'
        subprocess.run(['make', '-C', str(ROOT), 'install', f'DESTDIR={stage}', 'PREFIX=/usr',
                        'PYTHON=/usr/bin/python3'], check=True, stdout=subprocess.DEVNULL)
        vendor(wheels, stage / 'usr/share/libreward/vendor')
        documents = stage / 'usr/share/doc/libreward'
        documents.mkdir(parents=True)
        shutil.copy(ROOT / 'packaging/debian/copyright', documents / 'copyright')
        size = sum(path.stat().st_size for path in stage.rglob('*') if path.is_file()) // 1024
        debian = stage / 'DEBIAN'
        debian.mkdir()
        (debian / 'control').write_text(control(version, arguments.arch, size), encoding='utf-8')
        prerm = (ROOT / 'packaging/debian/libreward.prerm').read_text(encoding='utf-8')
        (debian / 'prerm').write_text(prerm.replace('#DEBHELPER#\n', ''), encoding='utf-8')
        (debian / 'prerm').chmod(0o755)
        for path in stage.rglob('*'):
            if path.is_dir():
                path.chmod(0o755)
        output.mkdir(parents=True, exist_ok=True)
        package = output / f'libreward_{version}_{arguments.arch}.deb'
        subprocess.run(['dpkg-deb', '--root-owner-group', '-Zxz', '--build', str(stage), str(package)], check=True)
    print(package)


if __name__ == '__main__':
    main()
