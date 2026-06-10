"""Cross-platform config management.

Uses paths provided by the platform backend.
- Windows: %APPDATA%\\LibreWard\\config.json
- Linux:   $XDG_CONFIG_HOME/libreward/config.json (~/.config/libreward/config.json)
"""

import json

from backends import backend


CONFIG_FILE = backend.config_dir() / "config.json"


def load_config() -> dict | None:
    """Load config from disk. Returns dict or None if file missing/corrupt."""
    try:
        if not CONFIG_FILE.exists():
            return None
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None


def save_config(data: dict) -> None:
    """Save config dict to disk. Raises on failure."""
    backend.config_dir().mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
