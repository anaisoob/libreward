"""Database update outcomes distinguish completion from background work."""
from dataclasses import dataclass


@dataclass(frozen=True)
class DatabaseUpdateResult:
    success: bool
    message: str
    pending: bool = False

    def __iter__(self):
        # Preserve the existing (success, output) unpacking API.
        yield self.success
        yield self.message
