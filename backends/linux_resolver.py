"""Read-only interpretation of Linux host-name resolution configuration."""
import re


def resolved_reads_hosts(config):
    enabled = True  # systemd-resolved's ReadEtcHosts default
    section = ''
    for line in config.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]
        elif section == 'Resolve' and '=' in line:
            key, value = (part.strip() for part in line.split('=', 1))
            if key == 'ReadEtcHosts':
                if value.lower() in ('yes', 'true', '1', 'on', ''):
                    enabled = True
                elif value.lower() in ('no', 'false', '0', 'off'):
                    enabled = False
                else:
                    return False
    return enabled


def nss_hosts_source(config, *, resolved_hosts=False):
    line = next((line.split('#', 1)[0] for line in config.splitlines()
                 if re.match(r'^\s*hosts\s*:', line)), '')
    if not line:
        return None
    tokens = re.findall(r'\[[^\]]*\]|[^\s]+', line.split(':', 1)[1])
    for index, source in enumerate(tokens):
        if source.startswith('['):
            continue
        if source == 'dns' or (source == 'resolve' and not resolved_hosts):
            return None
        if source == 'files' or (source == 'resolve' and resolved_hosts):
            actions = tokens[index + 1] if index + 1 < len(tokens) and tokens[index + 1].startswith('[') else ''
            # Do not declare success if NSS explicitly discards a hosts answer.
            if re.search(r'(?i)(?:SUCCESS|!(?:NOTFOUND|UNAVAIL|TRYAGAIN))\s*=\s*(?:continue|merge)', actions):
                continue
            return source
    return None
