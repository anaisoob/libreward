import json
from pathlib import Path


APP_NAME = "libreward"
CONFIG_DIR = Path.home() / ".config" / APP_NAME
CONFIG_FILE = CONFIG_DIR / "config.json"


def load_config():
    """Load config from disk. Returns dict or None if file missing/corrupt."""
    try:
        if not CONFIG_FILE.exists():
            return None
        return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return None


def save_config(data):
    """Save config dict to disk. Raises on failure."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
