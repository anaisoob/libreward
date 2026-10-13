"""Domain lists, validation and user preferences; no platform mutations."""
import gzip
from contextlib import closing
import hashlib
import ipaddress
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

CATEGORIES = {
    'dangerous': ('Dangerous websites and phishing', ('malware', 'phishing')),
    'tracking': ('Tracking', ('tracking',)),
    'ads': ('Ads', ('ads',)),
    'adult': ('Adult websites', ('porn',)),
}
SOURCE = 'https://raw.githubusercontent.com/blocklistproject/Lists/master/alt-version/{}-nl.txt'
MAX_DOWNLOAD = 64 * 1024 * 1024
MAX_CACHE = 256 * 1024 * 1024
MAX_DOMAINS = 5_000_000


def normalize_domain(value):
    if not isinstance(value, str):
        raise ValueError('Enter a domain name, for example example.org.')
    value = value.strip().rstrip('.').lower()
    if not value or any(char in value for char in '/:*?@#\\'):
        raise ValueError('Enter only the website domain, without https://, paths or wildcards.')
    try:
        value = value.encode('idna').decode('ascii')
        ipaddress.ip_address(value)
    except UnicodeError as exc:
        raise ValueError('This domain name is not valid.') from exc
    except ValueError:
        pass
    else:
        raise ValueError('Enter a domain name, not an IP address.')
    if re.fullmatch(r'[0-9.]+', value):
        raise ValueError('Enter a domain name, not an IP address.')
    if len(value) > 253 or '.' not in value or not all(
            re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in value.split('.')):
        raise ValueError('Enter a valid website domain, for example example.org.')
    if value == 'localhost.localdomain' or value.endswith(('.localhost', '.local', '.arpa')):
        raise ValueError('Local system names cannot be blocked.')
    return value


def domain_lines(text):
    domains = set()
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        try:
            domains.add(normalize_domain(line))
        except ValueError:
            continue
        if len(domains) > MAX_DOMAINS:
            raise ValueError('The domain list is too large.')
    return domains


def preferences(config):
    value = config.get('internet_protection', {})
    if not isinstance(value, dict):
        value = {}
    categories = value.get('categories', ['dangerous'])
    if not isinstance(categories, list) or any(not isinstance(item, str) or item not in CATEGORIES for item in categories):
        categories = ['dangerous']
    for key in ('allowed', 'blocked'):
        if not isinstance(value.get(key, []), list):
            raise ValueError('Saved website exceptions are invalid.')
    return {'categories': categories,
            'allowed': sorted({normalize_domain(item) for item in value.get('allowed', [])}),
            'blocked': sorted({normalize_domain(item) for item in value.get('blocked', [])})}


class DomainLists:
    def __init__(self, directory):
        self.path = Path(directory) / 'internet-protection' / 'lists.json.gz'

    def load(self):
        if not self.path.exists():
            return {'updated': None, 'lists': {}}
        with gzip.open(self.path, 'rb') as stream:
            data = stream.read(MAX_CACHE + 1)
        if len(data) > MAX_CACHE:
            raise ValueError('Saved lists are too large. Download them again.')
        bundle = json.loads(data)
        if not isinstance(bundle, dict) or not isinstance(bundle.get('lists'), dict):
            raise ValueError('Saved lists are invalid. Download them again.')
        for key, values in bundle['lists'].items():
            if key not in CATEGORIES or not isinstance(values, list) or len(values) > MAX_DOMAINS:
                raise ValueError('Saved lists are invalid. Download them again.')
            if any(normalize_domain(value) != value for value in values):
                raise ValueError('Saved lists are invalid. Download them again.')
        return bundle

    def update(self, categories, log=None):
        if any(not isinstance(key, str) or key not in CATEGORIES for key in categories):
            raise ValueError('Choose supported protection categories.')
        # Fetch all selected sources before replacing the last usable cache.
        lists = {}
        sources = []
        for key in categories:
            domains = set()
            for name in CATEGORIES[key][1]:
                if log:
                    log(f'Downloading {name} domain list from The Block List Project…\n')
                request = Request(SOURCE.format(name), headers={'User-Agent': 'LibreWard'})
                with urlopen(request, timeout=30) as response:
                    if not response.geturl().startswith('https://raw.githubusercontent.com/'):
                        raise ValueError('The list source redirected to an unexpected location.')
                    raw = response.read(MAX_DOWNLOAD + 1)
                if len(raw) > MAX_DOWNLOAD:
                    raise ValueError('Downloaded list is too large.')
                values = domain_lines(raw.decode('utf-8', errors='strict'))
                if not values:
                    raise ValueError(f'The {name} list contained no usable domains. Existing protection was kept.')
                domains.update(values)
                sources.append({'url': SOURCE.format(name), 'sha256': hashlib.sha256(raw).hexdigest(),
                                'header': '\n'.join(line for line in raw.decode('utf-8').splitlines()[:100]
                                                   if line.startswith('#'))})
            if len(domains) > MAX_DOMAINS:
                raise ValueError('The combined list is too large.')
            lists[key] = sorted(domains)
        bundle = {'updated': datetime.now(timezone.utc).isoformat(timespec='seconds'), 'lists': lists,
                  'sources': sources}
        encoded = json.dumps(bundle).encode('utf-8')
        if len(encoded) > MAX_CACHE:
            raise ValueError('The combined lists are too large.')
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=self.path.parent, prefix='.lists-')
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(gzip.compress(encoded))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.path)
        finally:
            if os.path.exists(name):
                os.unlink(name)
        return bundle

    def compile(self, settings):
        bundle = self.load()
        domains = set(settings['blocked'])
        for category in settings['categories']:
            if category not in bundle['lists']:
                raise ValueError('Download the selected protection lists first.')
            domains.update(bundle['lists'][category])
        domains.difference_update(settings['allowed'])
        if len(domains) > MAX_DOMAINS:
            raise ValueError('Too many blocked domains.')
        return sorted(domains)


def domain_digest(domains):
    return hashlib.sha256('\n'.join(sorted(domains)).encode('ascii')).hexdigest()


class DiskDomainLists(DomainLists):
    """Production cache: stream downloads into a bounded-cache SQLite database.

    load/update return metadata only, never millions of Python domain objects.
    Old JSON caches are intentionally not expanded; selected lists are fetched
    into the new format on the next update/apply.
    """
    def __init__(self, directory):
        self.path = Path(directory) / 'internet-protection' / 'lists.sqlite3'

    @staticmethod
    def connect(path):
        import sqlite3
        connection = sqlite3.connect(path)
        connection.execute('PRAGMA cache_size=-2048')
        connection.execute('PRAGMA temp_store=FILE')
        return connection

    def load(self):
        if not self.path.exists():
            return {'updated': None, 'lists': {}}
        with closing(self.connect(self.path)) as connection:
            metadata = json.loads(connection.execute('SELECT value FROM metadata').fetchone()[0])
            return metadata

    def update(self, categories, log=None):
        if any(not isinstance(key, str) or key not in CATEGORIES for key in categories):
            raise ValueError('Choose supported protection categories.')
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=self.path.parent, prefix='.lists-', suffix='.sqlite3')
        os.close(fd)
        connection = None
        try:
            connection = self.connect(name)
            connection.execute('CREATE TABLE domains (category TEXT, domain TEXT, PRIMARY KEY(category, domain)) WITHOUT ROWID')
            connection.execute('CREATE TABLE metadata (value TEXT)')
            sources, counts = [], {}
            for key in categories:
                for source in CATEGORIES[key][1]:
                    if log:
                        log(f'Downloading {source} domain list from The Block List Project…\n')
                    url = SOURCE.format(source)
                    digest, headers, total, usable = hashlib.sha256(), [], 0, 0
                    request = Request(url, headers={'User-Agent': 'LibreWard'})
                    with urlopen(request, timeout=30) as response:
                        if not response.geturl().startswith('https://raw.githubusercontent.com/'):
                            raise ValueError('The list source redirected to an unexpected location.')
                        while True:
                            raw = response.readline(4097)
                            if not raw:
                                break
                            total += len(raw)
                            if len(raw) > 4096 or total > MAX_DOWNLOAD:
                                raise ValueError('Downloaded list is too large or has invalid lines.')
                            digest.update(raw)
                            line = raw.decode('utf-8').strip()
                            if line.startswith('#') and len(headers) < 100:
                                headers.append(line)
                            line = line.split('#', 1)[0].strip()
                            if not line:
                                continue
                            try:
                                value = normalize_domain(line)
                            except ValueError:
                                continue
                            usable += 1
                            if usable > MAX_DOMAINS:
                                raise ValueError('The domain list is too large.')
                            connection.execute('INSERT OR IGNORE INTO domains VALUES (?, ?)', (key, value))
                    if not usable:
                        raise ValueError(f'The {source} list contained no usable domains. Existing protection was kept.')
                    sources.append({'url': url, 'sha256': digest.hexdigest(), 'header': '\n'.join(headers)})
                counts[key] = connection.execute('SELECT COUNT(*) FROM domains WHERE category=?', (key,)).fetchone()[0]
                if counts[key] > MAX_DOMAINS:
                    raise ValueError('The combined list is too large.')
            count = connection.execute('SELECT COUNT(DISTINCT domain) FROM domains').fetchone()[0]
            if count > MAX_DOMAINS:
                raise ValueError('The combined list is too large.')
            metadata = {'updated': datetime.now(timezone.utc).isoformat(timespec='seconds'),
                        'lists': counts, 'sources': sources, 'count': count}
            connection.execute('INSERT INTO metadata VALUES (?)', (json.dumps(metadata),))
            connection.commit()
            connection.close()
            connection = None
            with open(name, 'rb') as stream:
                os.fsync(stream.fileno())
            os.replace(name, self.path)
            return metadata
        finally:
            if connection is not None:
                connection.close()
            for path in (name, name + '-journal'):
                if os.path.exists(path):
                    os.unlink(path)

    def compile(self, settings):
        from .memory_budget import require_domain_memory
        if not self.path.exists():
            # Also keeps small in-memory callers compatible; production updates
            # create the database before applying selected categories.
            return super().compile(settings)
        with closing(self.connect(self.path)) as connection:
            connection.execute('CREATE TEMP TABLE selected (domain TEXT PRIMARY KEY) WITHOUT ROWID')
            available = self.load()['lists']
            for category in settings['categories']:
                if category not in available:
                    raise ValueError('Download the selected protection lists first.')
                connection.execute('INSERT OR IGNORE INTO selected SELECT domain FROM domains WHERE category=?', (category,))
            connection.executemany('INSERT OR IGNORE INTO selected VALUES (?)', ((normalize_domain(d),) for d in settings['blocked']))
            connection.executemany('DELETE FROM selected WHERE domain=?', ((normalize_domain(d),) for d in settings['allowed']))
            count = connection.execute('SELECT COUNT(*) FROM selected').fetchone()[0]
            if count > MAX_DOMAINS:
                raise ValueError('Too many blocked domains.')
            require_domain_memory(count)
            return [row[0] for row in connection.execute('SELECT domain FROM selected ORDER BY domain')]


    def prepare(self, settings):
        # No Python list/set of the selected domains is created on this path.
        database = self.path if self.path.exists() else ':memory:'
        with closing(self.connect(database)) as connection:
            connection.execute('CREATE TEMP TABLE selected (domain TEXT PRIMARY KEY) WITHOUT ROWID')
            available = self.load()['lists']
            for category in settings['categories']:
                if category not in available:
                    raise ValueError('Download the selected protection lists first.')
                connection.execute('INSERT OR IGNORE INTO selected SELECT domain FROM domains WHERE category=?', (category,))
            connection.executemany('INSERT OR IGNORE INTO selected VALUES (?)', ((normalize_domain(d),) for d in settings['blocked']))
            connection.executemany('DELETE FROM selected WHERE domain=?', ((normalize_domain(d),) for d in settings['allowed']))
            return prepare_domain_stream(connection, self.path.parent)


class PreparedDomains:
    """Disk-backed, single-use input to the privileged database installer."""
    def __init__(self, path, count, digest):
        self.path, self.count, self.digest = Path(path), count, digest

    def __len__(self):
        return self.count

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.path.unlink(missing_ok=True)


def prepare_domain_stream(connection, directory):
    count = connection.execute('SELECT COUNT(*) FROM selected').fetchone()[0]
    if count > MAX_DOMAINS:
        raise ValueError('Too many blocked domains.')
    Path(directory).mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=directory, prefix='.domains-', suffix='.txt')
    digest = hashlib.sha256()
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write((json.dumps({'version': 1, 'count': count}) + '\n').encode('ascii'))
            for row in connection.execute('SELECT domain FROM selected ORDER BY domain'):
                raw = row[0].encode('ascii') + b'\n'
                output.write(raw)
                digest.update(raw)
            output.flush()
            os.fsync(output.fileno())
        return PreparedDomains(name, count, digest.hexdigest())
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise



