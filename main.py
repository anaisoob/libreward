#!/usr/bin/env python3
"""Launch the LibreWard Qt desktop application."""
import argparse


def main():
    parser = argparse.ArgumentParser(description="LibreWard security and privacy desktop application")
    parser.add_argument("--qt", action="store_true", help=argparse.SUPPRESS)  # older launch commands
    parser.parse_args()
    try:
        from ui.main_window import run
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.startswith("PySide6"):
            parser.error("Install LibreWard dependencies first: python -m pip install -r requirements.txt")
        raise
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
