"""Bounded scan profiles shared by ClamD and clamscan."""
from dataclasses import dataclass
import os

MAX_WORKERS = 16


@dataclass(frozen=True)
class ScanLimits:
    file_size: str
    scan_size: str
    workers: int


def cpu_cores():
    return max(1, os.cpu_count() or 1)


def automatic_workers():
    """Half of the CPU cores (at least 1, at most 16) leaves the computer usable."""
    return max(1, min(cpu_cores() // 2, MAX_WORKERS))


def worker_choices():
    """Manual choices this computer can actually run: powers of two up to its cores."""
    limit = min(cpu_cores(), MAX_WORKERS)
    return [count for count in (1, 2, 4, 8, 16) if count <= limit]


def scan_limits(profile='standard', workers='auto'):
    if type(workers) is int and 1 <= workers <= min(cpu_cores(), MAX_WORKERS):
        count = workers
    else:
        count = automatic_workers()
    return (ScanLimits('1024M', '2048M', count) if profile == 'extended'
            else ScanLimits('100M', '400M', count))
