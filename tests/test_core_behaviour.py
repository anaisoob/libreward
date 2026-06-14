import re
import os
import shutil
import tempfile
import unittest
import zipfile
import json
from pathlib import Path

from backends.base import RuntimeInfo
from backends.windows import WindowsBackend
from excludes import build_clamscan_exclude_args, path_is_excluded
from scanner import parse_clamscan_result_line
import core.updater as updater
import core.quarantine as quarantine
import core.db_manager as db_manager


class FakeBackend:
    def __init__(self, root: Path, runtime: RuntimeInfo | None = None):
        self.root = root
        self.runtime = runtime or RuntimeInfo(
            source="user-updated",
            clamscan="clamscan.exe",
            freshclam="freshclam.exe",
            version="ClamAV 1.0.0",
            version_num="1.0.0",
        )

    def data_dir(self) -> Path:
        return self.root

    def updates_dir(self) -> Path:
        return self.root / "updates"

    def manages_own_runtime(self) -> bool:
        return True

    def platform_arch(self) -> str:
        return "windows-x64"

    def detect_clamav_runtime(self) -> RuntimeInfo:
        return self.runtime


class CoreBehaviourTests(unittest.TestCase):
    def test_windows_common_excludes_match_normalized_paths(self):
        patterns = WindowsBackend().default_common_excludes()["Git directories (.git)"]
        self.assertTrue(re.search(patterns[0], "C:/Users/me/project/.git/config", re.I))

    def test_posix_absolute_exclude_and_clamscan_arg(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            excluded = root / "skip"
            child = excluded / "file.txt"
            excluded.mkdir()
            child.write_text("x")

            self.assertTrue(path_is_excluded(str(child), [str(excluded)]))
            args = build_clamscan_exclude_args([str(excluded)])
            self.assertEqual(args, [f"--exclude-dir=^{re.escape(str(excluded))}"])

    def test_parse_clamscan_result_line_uses_last_separator(self):
        with tempfile.TemporaryDirectory() as tmp:
            file_path = str(Path(tmp) / "name:with:colon.txt")
            Path(file_path).write_text("x")
            parsed_path, status = parse_clamscan_result_line(
                f"{file_path}: OK\n", {str(Path(file_path).resolve())}
            )
            self.assertEqual(parsed_path, str(Path(file_path).resolve()))
            self.assertEqual(status, "OK")

    def test_check_for_updates_uses_only_minimal_version_key(self):
        old_backend = updater.backend
        old_fetch_manifest = updater.fetch_manifest
        try:
            with tempfile.TemporaryDirectory() as tmp:
                updater.backend = FakeBackend(Path(tmp))
                updater.fetch_manifest = lambda: {
                    "platforms": {
                        "windows-x64": {
                            "latest_version": "1.5.2",
                            "minimal_libreward_version": "9.9.9",
                            "download": {"url": "https://example.invalid/clamav.zip"},
                        }
                    }
                }
                self.assertIsNone(updater.check_for_updates())
        finally:
            updater.backend = old_backend
            updater.fetch_manifest = old_fetch_manifest

    def test_zip_extraction_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bad_zip = tmp_path / "bad.zip"
            with zipfile.ZipFile(bad_zip, "w") as zf:
                zf.writestr("../escape.txt", "bad")

            with self.assertRaises(RuntimeError):
                updater._extract_zip(bad_zip, tmp_path / "out")

    def test_runtime_install_restores_previous_on_final_move_failure(self):
        old_backend = updater.backend
        original_move = shutil.move
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                updater.backend = FakeBackend(root)
                current = root / "clamav-runtime" / "current"
                current.mkdir(parents=True)
                (current / "old.txt").write_text("old")

                new_runtime = root / "new-runtime"
                new_runtime.mkdir()
                (new_runtime / "new.txt").write_text("new")

                def failing_move(src, dst, *args, **kwargs):
                    if Path(src).name == "current.installing" and Path(dst).name == "current":
                        raise RuntimeError("forced final move failure")
                    return original_move(src, dst, *args, **kwargs)

                updater.shutil.move = failing_move

                with self.assertRaises(RuntimeError):
                    updater._install_runtime_with_rollback(new_runtime)

                self.assertEqual((current / "old.txt").read_text(), "old")
        finally:
            updater.shutil.move = original_move
            updater.backend = old_backend

    def test_runtime_validation_error_explains_windows_dll_failure(self):
        msg = updater._format_validation_failure(
            "clamscan.exe --version",
            3221225781,
            "",
            "",
        )
        self.assertIn("0xC0000135", msg)
        self.assertIn("DLL", msg)

    def test_runtime_validation_env_prefixes_runtime_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime_dir = Path(tmp)
            env = updater._runtime_validation_env(runtime_dir)
            path_key = next(k for k in env if k.upper() == "PATH")
            first_path = env[path_key].split(os.pathsep)[0]
            self.assertEqual(first_path, str(runtime_dir))

    def test_generated_freshclam_conf_uses_supported_options(self):
        old_backend = db_manager.backend
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)

                class B:
                    def manages_own_database(self):
                        return True

                    def db_dir(self):
                        return root / "clamav-db"

                    def log_dir(self):
                        return root / "logs"

                    def data_dir(self):
                        return root

                db_manager.backend = B()
                conf_path = Path(db_manager.generate_freshclam_conf("freshclam.exe"))
                text = conf_path.read_text(encoding="utf-8")
                self.assertIn("DatabaseDirectory", text)
                self.assertIn("Foreground yes", text)
                self.assertNotIn("ScriptedSecurity", text)
        finally:
            db_manager.backend = old_backend

    def test_quarantine_list_and_delete(self):
        old_backend = quarantine.backend
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                quarantine.backend = type(
                    "B",
                    (),
                    {"quarantine_dir": lambda self: root / "quarantine"},
                )()
                qdir = root / "quarantine"
                qdir.mkdir()
                qfile = qdir / "abc_sample.exe"
                qfile.write_text("payload")
                (qdir / "abc_sample.exe.json").write_text(
                    "{"
                    '"schema_version": 1,'
                    '"original_path": "/tmp/sample.exe",'
                    '"threat_name": "Eicar-Test",'
                    '"quarantined_at": "2026-06-10T00:00:00Z",'
                    '"original_size": 7,'
                    '"quarantine_name": "abc_sample.exe"'
                    "}"
                )

                items = quarantine.list_quarantined_files()
                self.assertEqual(len(items), 1)
                self.assertEqual(items[0]["quarantine_name"], "abc_sample.exe")

                msg = quarantine.delete_quarantined_file("abc_sample.exe")
                self.assertIn("Permanently deleted", msg)
                self.assertFalse(qfile.exists())
                self.assertEqual(quarantine.list_quarantined_files(), [])
        finally:
            quarantine.backend = old_backend

    def test_quarantine_restore_refuses_overwrite_by_default(self):
        old_backend = quarantine.backend
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                quarantine.backend = type(
                    "B",
                    (),
                    {"quarantine_dir": lambda self: root / "quarantine"},
                )()
                original = root / "sample.exe"
                original.write_text("existing")

                qdir = root / "quarantine"
                qdir.mkdir()
                qfile = qdir / "abc_sample.exe"
                qfile.write_text("quarantined")
                (qdir / "abc_sample.exe.json").write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "original_path": str(original),
                            "threat_name": "Eicar-Test",
                            "quarantined_at": "2026-06-10T00:00:00Z",
                            "original_size": 11,
                            "quarantine_name": "abc_sample.exe",
                        }
                    ),
                    encoding="utf-8",
                )

                msg = quarantine.restore_file("abc_sample.exe")
                self.assertIn("Original file already exists", msg)
                self.assertEqual(original.read_text(), "existing")
                self.assertTrue(qfile.exists())

                msg = quarantine.restore_file("abc_sample.exe", overwrite=True)
                self.assertIn("Restored", msg)
                self.assertEqual(original.read_text(), "quarantined")
                self.assertFalse(qfile.exists())
        finally:
            quarantine.backend = old_backend

    def test_windows_runtime_manifest_uses_canonical_schema(self):
        manifest_path = Path(__file__).resolve().parents[1] / "updates" / "clamav-runtime-windows.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(manifest["product"], "LibreWard")
        self.assertEqual(manifest["component"], "clamav-runtime")

        for entry in manifest["platforms"].values():
            self.assertIn("minimal_libreward_version", entry)
            self.assertNotIn("minimum_libreward_version", entry)
            self.assertEqual(
                entry["download"]["runtime_root_mode"],
                "contents-of-extract-dir",
            )
            self.assertTrue(entry["download"]["url"].startswith("https://github.com/Cisco-Talos/clamav/"))
            self.assertRegex(entry["download"]["sha256"], r"^[a-f0-9]{64}$")
            self.assertIn("clamscan.exe --version", entry["validation"]["commands"])
            self.assertIn("freshclam.exe --version", entry["validation"]["commands"])


if __name__ == "__main__":
    unittest.main()
