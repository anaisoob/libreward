#!/usr/bin/env python3
"""Launch the LibreWard Qt desktop application."""
import argparse


def main():
    parser = argparse.ArgumentParser(description="LibreWard security and privacy desktop application")
    parser.add_argument("--qt", action="store_true", help=argparse.SUPPRESS)  # older launch commands
    # Login autostart entries of earlier versions: removed on launch, nothing is shown.
    parser.add_argument("--autostart", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--monitor", action="store_true",
                        help="run folder monitoring in the background (started by the user service)")
    args = parser.parse_args()
    if args.monitor:
        # Headless: no Qt, so the agent also runs before or without a desktop session.
        from core.monitor_agent import main as monitor
        return monitor()
    try:
        from ui.main_window import run
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.startswith("PySide6"):
            parser.error("Install LibreWard dependencies first: python -m pip install -r requirements.txt")
        raise
    return run(autostart=args.autostart)


if __name__ == "__main__":
    raise SystemExit(main())
