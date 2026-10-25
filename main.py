#!/usr/bin/env python3
"""Launch the LibreWard Qt desktop application."""
import argparse
import sys


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
    from core.dependencies import missing_components, missing_message
    missing = missing_components(["pyside6", "qtnetwork"])
    if missing:
        # Started from the desktop menu there is no terminal: show it there too.
        from backends import backend
        message = missing_message(missing, "LibreWard")
        print(message, file=sys.stderr)
        for component, reason in missing.items():
            print(f"{component}: {reason}", file=sys.stderr)
        if not args.autostart:
            backend.show_error_without_gui("LibreWard cannot start", message)
        return 1
    from ui.main_window import run
    return run(autostart=args.autostart)


if __name__ == "__main__":
    raise SystemExit(main())
