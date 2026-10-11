"""Bounded scan profiles shared by ClamD and clamscan."""
from dataclasses import dataclass


@dataclass(frozen=True)
class ScanLimits:
    file_size: str
    scan_size: str
    workers: int


def scan_limits(profile='standard'):
    return ScanLimits('1024M', '2048M', 2) if profile == 'extended' else ScanLimits('100M', '400M', 4)
