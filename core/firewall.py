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
