"""Bounded scan profiles shared by ClamD and clamscan."""
from dataclasses import dataclass
import os


@dataclass(frozen=True)
class ScanLimits:
    file_size: str
    scan_size: str
    workers: int


def scan_limits(profile='standard', workers='auto'):
    if type(workers) is int and workers in (4, 8, 16):
        count = workers
    else:
        count = max(1, min(os.cpu_count() or 1, 16))
        if profile == 'extended':
            count = min(count, 2)
    return (ScanLimits('1024M', '2048M', count) if profile == 'extended'
            else ScanLimits('100M', '400M', count))
