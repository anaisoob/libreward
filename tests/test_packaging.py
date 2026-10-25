"""`make install` layout used by the Arch, RPM and Debian packages."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


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
            self.assertIn(f'exec {sys.executable} -s -E /usr/share/libreward/main.py "$@"\n', launcher)
            self.assertTrue(os.access(root / 'usr/bin/libreward', os.X_OK))
            desktop = (root / 'usr/share/applications/libreward.desktop').read_text()
            self.assertIn('\nExec=libreward\n', desktop)
            self.assertIn('\nIcon=libreward\n', desktop)
            for icon in ('scalable/apps/libreward.svg', '256x256/apps/libreward.png'):
                self.assertTrue((root / 'usr/share/icons/hicolor' / icon).is_file(), icon)

    def test_appstream_metadata_is_installed_and_consistent(self):
        import re
        import xml.etree.ElementTree as ElementTree
        source = ROOT / 'packaging/io.github.anaisoob.LibreWard.metainfo.xml'
        component = ElementTree.parse(source).getroot()
        self.assertEqual(component.get('type'), 'desktop-application')
        self.assertEqual(component.findtext('id'), 'io.github.anaisoob.LibreWard')
        self.assertEqual(component.findtext('project_license'), 'GPL-2.0-or-later')
        self.assertEqual(component.findtext('launchable'), 'libreward.desktop')
        self.assertTrue((ROOT / 'packaging' / component.findtext('launchable')).is_file())
        self.assertIsNotNone(component.find('content_rating'))
        screenshot = component.findtext('screenshots/screenshot/image')
        self.assertTrue(screenshot.endswith('/main/assets/libreward.png'))
        self.assertTrue((ROOT / 'assets/libreward.png').is_file())
        # The newest release matches the newest released CHANGELOG section.
        newest = component.find('releases/release')
        released = re.search(r'^## (\d+\.\d+\.\d+) — (\d{4}-\d{2}-\d{2})$',
                             (ROOT / 'CHANGELOG.md').read_text(), re.M)
        self.assertEqual((newest.get('version'), newest.get('date')), released.groups())
        with tempfile.TemporaryDirectory() as directory:
            installed = self.install(directory) / 'usr/share/metainfo/io.github.anaisoob.LibreWard.metainfo.xml'
            self.assertEqual(installed.read_bytes(), source.read_bytes())
        self.assertIn('%{_metainfodir}/io.github.anaisoob.LibreWard.metainfo.xml',
                      (ROOT / 'packaging/rpm/libreward.spec').read_text())

    def test_cleanup_script_is_installed_and_run_only_on_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.install(directory)
            self.assertTrue((root / 'usr/share/libreward/system_cleanup.py').is_file())
        command = 'python3 -I /usr/share/libreward/system_cleanup.py || '
        spec = (ROOT / 'packaging/rpm/libreward.spec').read_text()
        self.assertIn('%preun\n', spec)
        self.assertIn('if [ $1 -eq 0 ]; then\n    %{__python3} -I %{_datadir}/libreward/system_cleanup.py || :', spec)
        prerm = (ROOT / 'packaging/debian/libreward.prerm').read_text()
        self.assertIn('if [ "$1" = "remove" ]; then\n    ' + command + 'true', prerm)
        self.assertIn('#DEBHELPER#', prerm)
        self.assertTrue(os.access(ROOT / 'packaging/debian/libreward.prerm', os.X_OK))
        self.assertIn('\ninstall=libreward.install\n', (ROOT / 'packaging/arch/PKGBUILD').read_text())
        arch = (ROOT / 'packaging/arch/libreward.install').read_text()
        self.assertIn('pre_remove() {\n  /usr/bin/' + command + 'true', arch)
        self.assertNotIn('post_upgrade', arch)

    def test_package_versions_match(self):
        import re
        versions = {
            'PKGBUILD': re.search(r'^pkgver=(\S+)$', (ROOT / 'packaging/arch/PKGBUILD').read_text(), re.M).group(1),
            'spec': re.search(r'^Version:\s+(\S+)$', (ROOT / 'packaging/rpm/libreward.spec').read_text(), re.M).group(1),
            'debian': re.search(r'^libreward \(([^-)]+)', (ROOT / 'packaging/debian/changelog').read_text()).group(1),
            'obs': re.search(r'^Version: ([^-]+)-', (ROOT / 'packaging/obs/libreward.dsc').read_text(), re.M).group(1),
        }
        self.assertEqual(len(set(versions.values())), 1, versions)
