"""Public filtering DNS services offered where the local filter is unavailable.

Addresses and DNS-over-TLS names come from each provider's official setup page.
LibreWard is not affiliated with these services; they are used under their own terms.
"""
import ipaddress
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class DnsProvider:
    key: str
    name: str
    blocks: str
    addresses: tuple
    tls_name: str
    homepage: str

    def servers(self):
        """resolved.conf DNS= entries; the #name enables certificate checks for DNS-over-TLS."""
        return tuple(f'{address}#{self.tls_name}' for address in self.addresses)


PROVIDERS = {provider.key: provider for provider in (
    DnsProvider('adguard', 'AdGuard DNS', 'Blocks ads, trackers, malware and phishing.',
                ('94.140.14.14', '94.140.15.15', '2a10:50c0::ad1:ff', '2a10:50c0::ad2:ff'),
                'dns.adguard-dns.com', 'https://adguard-dns.io/'),
    DnsProvider('adguard-family', 'AdGuard DNS Family', 'Blocks ads, trackers, malware, phishing and adult content, '
                'and turns on Safe Search in search engines.',
                ('94.140.14.15', '94.140.15.16', '2a10:50c0::bad1:ff', '2a10:50c0::bad2:ff'),
                'family.adguard-dns.com', 'https://adguard-dns.io/'),
    DnsProvider('quad9', 'Quad9', 'Blocks malware and phishing. Run by a non-profit foundation.',
                ('9.9.9.9', '149.112.112.112', '2620:fe::fe', '2620:fe::9'),
                'dns.quad9.net', 'https://quad9.net/'),
    DnsProvider('cloudflare-security', 'Cloudflare (malware blocking)', 'Blocks malware.',
                ('1.1.1.2', '1.0.0.2', '2606:4700:4700::1112', '2606:4700:4700::1002'),
                'security.cloudflare-dns.com', 'https://one.one.one.one/family/'),
    DnsProvider('cloudflare-family', 'Cloudflare for Families', 'Blocks malware and adult content.',
                ('1.1.1.3', '1.0.0.3', '2606:4700:4700::1113', '2606:4700:4700::1003'),
                'family.cloudflare-dns.com', 'https://one.one.one.one/family/'),
)}
DEFAULT_PROVIDER = 'adguard'


def validate_providers(providers=PROVIDERS):
    """Fail early if a table edit would put unexpected text into root-written files."""
    for key, provider in providers.items():
        if key != provider.key or not re.fullmatch(r'[a-z0-9-]+', key):
            raise ValueError('Invalid DNS provider key.')
        if not re.fullmatch(r'[a-z0-9.-]+', provider.tls_name) or not provider.addresses:
            raise ValueError('Invalid DNS provider name.')
        for address in provider.addresses:
            ipaddress.ip_address(address)


validate_providers()
