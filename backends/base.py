from abc import ABC, abstractmethod


class PlatformBackend(ABC):
    """Abstract interface for OS-specific operations.

    Every platform (Linux, Windows) provides its own concrete backend.
    The GUI and core logic must never branch on OS directly — they call
    methods on the active backend instance.
    """

    @abstractmethod
    def start_process(self, cmd, **kwargs):
        """Start a subprocess with platform-appropriate process-group handling.

        Returns a subprocess.Popen instance.
        """
        ...

    @abstractmethod
    def stop_process(self, process):
        """Gracefully terminate a process started by start_process()."""
        ...

    @abstractmethod
    def find_clamscan(self) -> str | None:
        """Return path to clamscan binary, or None."""
        ...

    @abstractmethod
    def find_freshclam(self) -> str | None:
        """Return path to freshclam binary, or None."""
        ...

    @abstractmethod
    def default_common_excludes(self) -> dict[str, list[str]]:
        """Return platform-appropriate default exclude patterns.

        Keys are human-readable labels, values are lists of regex patterns
        or absolute-path prefixes.
        """
        ...
