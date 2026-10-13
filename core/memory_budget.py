"""Conservative application-work budgets, including Linux container limits."""
from pathlib import Path

MIB = 1024 * 1024


def available_memory():
    values = []
    try:
        for line in Path('/proc/meminfo').read_text().splitlines():
            if line.startswith('MemAvailable:'):
                values.append(int(line.split()[1]) * 1024)
    except (OSError, ValueError):
        pass
    # The process can be capped far below the machine's reported free RAM.
    try:
        group = next(line.split(':', 2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines()
                     if line.startswith('0::'))
        root = Path('/sys/fs/cgroup')
        folder = root / group.lstrip('/')
        if '..' not in Path(group).parts:
            while True:
                try:
                    limit = (folder / 'memory.max').read_text().strip()
                    if limit != 'max':
                        current = int((folder / 'memory.current').read_text())
                        values.append(max(0, int(limit) - current))
                except (OSError, ValueError):
                    pass
                if folder == root:
                    break
                folder = folder.parent
    except (OSError, ValueError, StopIteration):
        pass
    return min(values) if values else 512 * MIB


def require_domain_memory(count):
    # Covers Python/helper copies, DNS records and replacement of an active list.
    # This is an estimate, not a guarantee against other processes consuming RAM.
    estimated = count * 1536
    available = available_memory()
    budget = max(0, min(available // 2, available - 512 * MIB))
    if estimated > budget:
        raise ValueError('There is not enough available memory to safely enable this protection list '
                         f'({count:,} domains). Choose fewer categories or free some memory and try again. '
                         'Existing protection settings have not been changed.')
