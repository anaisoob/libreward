"""`make install` layout used by the Arch, RPM and Debian packages."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent


@unittest.skipUnless(shutil.which('make') and os.name == 'posix', 'make is required')
class InstallLayoutTests(unittest.TestCase):
    def install(self, directory):
        subprocess.run(['make', '-s', '-C', str(ROOT), 'install', f'DESTDIR={directory}', 'PREFIX=/usr',
                        f'PYTHON={sys.executable}'], check=True, capture_output=True)
        return Path(directory)

    def test_every_application_module_is_installed(self):
        with tempfile.TemporaryDirectory() as directory:
            app = self.install(directory) / 'usr/share/libreward'
            sources = [path.relative_to(ROOT) for path in ROOT.glob('*.py')]
            sources += [path.relative_to(ROOT) for package in ('backends', 'core', 'ui')
                        for path in (ROOT / package).glob('*.py')]
            missing = [str(path) for path in sources if not (app / path).is_file()]
            self.assertEqual(missing, [])
            self.assertTrue((app / 'updates/clamav-runtime-windows.json').is_file())
            self.assertTrue(list((app / 'core/__pycache__').glob('*.pyc')))

    def test_launcher_desktop_entry_and_icons(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.install(directory)
            launcher = (root / 'usr/bin/libreward').read_text()
            self.assertIn('LIBREWARD_LAUNCHER=/usr/bin/libreward\n', launcher)
            self.assertIn(f'exec {sys.executable} -s -E /usr/share/libreward/main.py "$@"\n', launcher)
            self.assertTrue(os.access(root / 'usr/bin/libreward', os.X_OK))
            desktop = (root / 'usr/share/applications/libreward.desktop').read_text()
            self.assertIn('\nExec=libreward\n', desktop)
            self.assertIn('\nIcon=libreward\n', desktop)
            for icon in ('scalable/apps/libreward.svg', '256x256/apps/libreward.png'):
                self.assertTrue((root / 'usr/share/icons/hicolor' / icon).is_file(), icon)

    def test_package_versions_match(self):
        import re
        versions = {
            'PKGBUILD': re.search(r'^pkgver=(\S+)$', (ROOT / 'packaging/arch/PKGBUILD').read_text(), re.M).group(1),
            'spec': re.search(r'^Version:\s+(\S+)$', (ROOT / 'packaging/rpm/libreward.spec').read_text(), re.M).group(1),
            'debian': re.search(r'^libreward \(([^-)]+)', (ROOT / 'packaging/debian/changelog').read_text()).group(1),
            'obs': re.search(r'^Version: ([^-]+)-', (ROOT / 'packaging/obs/libreward.dsc').read_text(), re.M).group(1),
        }
        self.assertEqual(len(set(versions.values())), 1, versions)


@unittest.skipUnless(os.name == 'posix', 'XDG autostart is Linux-specific')
class InstalledAutostartTests(unittest.TestCase):
    def test_installed_app_autostarts_through_its_launcher(self):
        from backends.linux import LinuxBackend
        with tempfile.TemporaryDirectory() as directory:
            launcher = Path(directory, 'libreward')
            launcher.write_text('#!/bin/sh\n')
            launcher.chmod(0o755)
            with patch.dict(os.environ, {'XDG_CONFIG_HOME': directory, 'LIBREWARD_LAUNCHER': str(launcher)}):
                LinuxBackend.__new__(LinuxBackend).set_autostart(True)
            text = Path(directory, 'autostart', 'libreward.desktop').read_text()
            self.assertIn(f'Exec="{launcher}" "--autostart"\n', text)
            self.assertIn('\nIcon=libreward\n', text)
