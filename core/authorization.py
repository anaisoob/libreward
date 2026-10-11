"""Shared authorization outcomes; platform commands belong to backends."""
from dataclasses import dataclass


@dataclass(frozen=True)
class AuthorizationStatus:
    available: bool
    message: str
    install_command: str = ''


class AuthorizationError(RuntimeError):
    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class PackageInstallPlan:
    manager: str
    command: str
    packages: tuple[str, ...]
    explanation: str
