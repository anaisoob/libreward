"""Shared firewall inspection models and structured rule validation."""
from dataclasses import dataclass, field


@dataclass
class FirewallTool:
    name: str
    state: str
    rules: str
    command: str


@dataclass
class FirewallSnapshot:
    supported: bool = False
    tools: list[FirewallTool] = field(default_factory=list)
    instructions: str = "Firewall inspection is currently available on Linux."


@dataclass(frozen=True)
class FirewallRule:
    action: str
    direction: str
    scope: str
    protocol: str
    port: str
    subnet: str = ''
    zone: str = ''
    lifetime: str = 'runtime'

    def validated(self):
        """Validate structured input before constructing any privileged command."""
        import ipaddress
        import re
        from dataclasses import replace
        if not all(isinstance(value, str) for value in (self.action, self.direction, self.scope, self.protocol, self.port, self.subnet, self.zone, self.lifetime)):
            raise ValueError('Firewall rule fields must be text.')
        if self.action not in ('allow', 'deny'):
            raise ValueError('Choose Allow or Block.')
        if self.direction not in ('in', 'out', 'both'):
            raise ValueError('Choose incoming, outgoing or both directions.')
        if self.scope not in ('lan', 'internet'):
            raise ValueError('Choose LAN or Internet / all addresses.')
        if self.protocol not in ('tcp', 'udp'):
            raise ValueError('Choose TCP or UDP.')
        port = self.port.strip()
        if not re.fullmatch(r'[0-9]{1,5}(-[0-9]{1,5})?', port):
            raise ValueError('Enter a port (1–65535) or range, for example 8000-8010.')
        numbers = [int(value) for value in port.split('-')]
        if any(value < 1 or value > 65535 for value in numbers) or numbers[0] > numbers[-1]:
            raise ValueError('Ports must be between 1 and 65535, with the range in ascending order.')
        port = '-'.join(str(value) for value in numbers)
        subnet = ''
        if self.scope == 'lan':
            try:
                network = ipaddress.ip_network(self.subnet.strip(), strict=False)
            except ValueError as exc:
                raise ValueError('Enter a valid LAN network in CIDR notation, for example 192.168.1.0/24.') from exc
            if network.prefixlen == 0 or network.is_multicast or network.is_unspecified or network.is_loopback:
                raise ValueError('Choose a specific LAN network, not all addresses, loopback or multicast.')
            subnet = str(network)
        zone = self.zone.strip()
        if zone and not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_-]{0,63}', zone):
            raise ValueError('Enter a valid firewalld zone name.')
        if self.lifetime not in ('runtime', 'permanent'):
            raise ValueError('Choose current-session or saved firewalld configuration.')
        return replace(self, port=port, subnet=subnet, zone=zone)

    def description(self, tool_name):
        rule = self.validated()
        direction = {'in': 'incoming', 'out': 'outgoing', 'both': 'incoming and outgoing'}[rule.direction]
        target = f'LAN {rule.subnet}' if rule.scope == 'lan' else 'all addresses, including LAN and Internet'
        text = f"{rule.action.capitalize()} {direction} {rule.protocol.upper()} traffic on destination port {rule.port}, for {target}."
        if tool_name == 'UFW':
            text += '\nUFW saves the rule and applies it immediately if active. If inactive, it takes effect when UFW is enabled.'
        else:
            text += f'\nfirewalld zone: {rule.zone}.'
            text += (' Applies immediately; lost when firewalld reloads or restarts.' if rule.lifetime == 'runtime' else
                     ' Saved only; takes effect on the next firewalld reload/restart. Current rules are unchanged.')
        text += '\nExisting rules and their order can affect the result. This does not configure your router or port forwarding.'
        return text


@dataclass
class FirewallChangeResult:
    success: bool
    message: str
    snapshot: FirewallSnapshot
    refresh_error: str = ''


@dataclass(frozen=True)
class FirewallRemoval:
    """Identity of one saved UFW rule or firewalld zone entry."""
    text: str
    kind: str = 'ufw'
    zone: str = ''
    permanent: bool = False

    def arguments(self, tool_name):
        import re
        import shlex
        if not isinstance(self.text, str) or not self.text or '\n' in self.text or '\r' in self.text:
            raise ValueError('Select a valid rule to remove.')
        if tool_name == 'UFW' and self.kind == 'ufw':
            parts = shlex.split(self.text)
            if len(parts) < 3 or parts[0] != 'ufw' or parts[1] not in ('allow', 'deny', 'reject', 'limit'):
                raise ValueError('This UFW rule cannot be removed here.')
            # UFW show added emits rule syntax, never global command options.
            if any(part.startswith('-') for part in parts[2:]):
                raise ValueError('Unsupported UFW rule option.')
            return 'ufw', ['--force', 'delete', *parts[1:]]
        if tool_name == 'firewalld' and self.kind in ('service', 'port', 'rich-rule'):
            if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_-]{0,63}', self.zone):
                raise ValueError('Select a valid connection zone.')
            if self.kind == 'service' and not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*', self.text):
                raise ValueError('Invalid service.')
            if self.kind == 'port' and not re.fullmatch(r'[0-9]+(-[0-9]+)?/(tcp|udp|sctp|dccp)', self.text):
                raise ValueError('Invalid port.')
            if self.kind == 'rich-rule' and not self.text.startswith('rule '):
                raise ValueError('Invalid connection rule.')
            return 'firewall-cmd', [*(['--permanent'] if self.permanent else []),
                                   '--zone=' + self.zone, '--remove-' + self.kind + '=' + self.text]
        raise ValueError('Removing rules is supported for UFW and firewalld only.')

    def description(self, tool_name):
        if tool_name == 'UFW':
            return self.text + '\nSaved rule; applies to both IP versions when the rule covers both.'
        return f'{self.text}\nZone: {self.zone} · ' + ('Saved configuration (after reload)' if self.permanent else 'Current session')


def removable_firewall_rules(tool):
    """Only expose explicitly identified entries, never infer rules from errors."""
    import re
    entries = []
    zone, permanent, rich = '', False, False
    for line in tool.rules.splitlines():
        text = line.strip()
        if tool.name == 'UFW':
            if text.startswith('ufw '):
                candidate = FirewallRemoval(text)
                try:
                    candidate.arguments('UFW')
                except ValueError:
                    continue
                if candidate not in entries:
                    entries.append(candidate)
            continue
        if tool.name != 'firewalld':
            continue
        if text.startswith('Permanent zones'):
            permanent, zone, rich = True, '', False
            continue
        if text.startswith('Runtime zones'):
            permanent, zone, rich = False, '', False
            continue
        if line and not line[0].isspace() and re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_-]*(?: \(.*\))?', line):
            zone, rich = line.split()[0], False
            continue
        if not zone:
            continue
        if text.startswith(('services:', 'ports:')):
            label, values = text.split(':', 1)
            entries.extend(FirewallRemoval(value, 'service' if label == 'services' else 'port', zone, permanent)
                           for value in values.split())
            rich = False
        elif text == 'rich rules:':
            rich = True
        elif rich and text.startswith('rule '):
            entries.append(FirewallRemoval(text, 'rich-rule', zone, permanent))
        elif text:
            rich = False
    return entries


def firewall_rule_columns(entry, tool):
    """Conservative human-readable labels; unknown conditions stay explicit."""
    import shlex
    scope = 'Saved · firewall is off' if tool.state == 'Inactive' else 'Saved · applies when firewall is on'
    if tool.name == 'firewalld':
        scope = ('Saved · after reload' if entry.permanent else 'Active session') + f' · {entry.zone}'
        if entry.kind in ('service', 'port'):
            return ('Allow', 'To this computer', entry.text, 'Zone connections', scope)
        return ('Custom rule', 'See details', 'Custom conditions', 'See details', scope)
    parts = shlex.split(entry.text)[1:]
    action = {'allow': 'Allow', 'deny': 'Block', 'reject': 'Block (reject)', 'limit': 'Limit connections'}[parts[0]]
    tokens = parts[1:]
    direction = 'From this computer' if tokens and tokens[0] == 'out' else 'To this computer'
    if tokens and tokens[0] in ('in', 'out'):
        tokens = tokens[1:]
    # Keep uncommon UFW syntax visible without guessing its meaning.
    if 'comment' in tokens:
        tokens = tokens[:tokens.index('comment')]
    if len(tokens) == 1:
        return action, direction, tokens[0], 'All networks', scope
    if 'on' in tokens or 'log' in tokens or 'log-all' in tokens:
        return action, direction, 'Custom conditions', 'See details', scope
    if 'from' in tokens and 'to' in tokens:
        source = tokens[tokens.index('from') + 1]
        target = tokens[tokens.index('to') + 1]
        network = source if direction == 'To this computer' else target
        # Destination address constraints remain visible too.
        if source != 'any' and target != 'any':
            network = f'{source} → {target}'
        elif network == 'any':
            other = target if direction == 'To this computer' else source
            network = 'All networks' if other == 'any' else f'Address: {other}'
        port = tokens[tokens.index('port') + 1] if 'port' in tokens else 'All ports'
        protocol = tokens[tokens.index('proto') + 1].upper() if 'proto' in tokens else ''
        if tokens.count('port') > 1 or 'app' in tokens:
            port = 'Custom conditions'
        return action, direction, f'{port} {protocol}'.strip(), network, scope
    return action, direction, 'Custom conditions', 'See details', scope
