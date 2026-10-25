"""Check optional and required components and explain how to install them.

Components: 'pyside6' (the GUI), 'qtnetwork' (single-instance launch),
'watchdog' (folder monitoring) and 'notify-send' (Linux desktop notifications).
The platform backend supplies the install commands; this module never imports Qt.
"""
from importlib import import_module

from backends import backend

PYTHON_MODULES = {
    'pyside6': ('PySide6.QtWidgets',),
    'qtnetwork': ('PySide6.QtNetwork',),
    'watchdog': ('watchdog.observers', 'watchdog.events'),
}
LABELS = {
    'pyside6': 'PySide6 (Qt for Python)',
    'qtnetwork': 'the PySide6 network module',
    'watchdog': 'watchdog',
    'notify-send': 'notify-send (libnotify)',
}


def missing_components(components):
    """{component: reason} for Python components that cannot be imported."""
    missing = {}
    for component in components:
        for module in PYTHON_MODULES[component]:
            try:
                import_module(module)
            except ImportError as exc:  # also a module whose system libraries are missing
                missing[component] = str(exc) or module
                break
    return missing


def install_hint(components):
    commands = backend.dependency_install_commands(list(components))
    if not commands:
        return 'Install ' + ', '.join(LABELS[component] for component in components) + ' with your package manager.'
    return ('Install with:\n' if len(commands) == 1 else 'Install with these commands:\n') + '\n'.join(commands)


def missing_message(components, needed_for):
    """User-facing explanation, for example missing_message({'watchdog': …}, 'Folder monitoring')."""
    names = ' and '.join(LABELS[component] for component in components)
    return f'{needed_for} needs {names}, which is not installed or cannot be loaded.\n{install_hint(components)}'
