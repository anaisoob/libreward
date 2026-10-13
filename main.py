#!/usr/bin/env python3
"""Launch the LibreWard Qt desktop application."""
import argparse


def main():
    parser = argparse.ArgumentParser(description="LibreWard security and privacy desktop application")
    parser.add_argument("--qt", action="store_true", help=argparse.SUPPRESS)  # older launch commands
    # Login autostart entries of earlier versions: removed on launch, nothing is shown.
    parser.add_argument("--autostart", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        from ui.main_window import run
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.startswith("PySide6"):
            parser.error("Install LibreWard dependencies first: python -m pip install -r requirements.txt")
        raise
    return run(autostart=args.autostart)


if __name__ == "__main__":
    raise SystemExit(main())
