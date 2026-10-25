"""Public DNS services used by Internet protection, always over DNS-over-TLS.

Simple protection uses a protective service that blocks websites itself.
Advanced protection uses LibreWard's own lists and a service that blocks nothing,
so allowed websites really open; on NetworkManager it can also use the network's
own DNS servers ('network').

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
    about: str  # one plain sentence for the page
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
    # Services that block nothing, for LibreWard's own lists.
    DnsProvider('quad9-unfiltered', 'Quad9', 'Run by a non-profit foundation in Switzerland.',
                ('9.9.9.10', '149.112.112.10', '2620:fe::10', '2620:fe::fe:10'),
                'dns10.quad9.net', 'https://quad9.net/'),
    DnsProvider('cloudflare', 'Cloudflare', 'Run by the company Cloudflare.',
                ('1.1.1.1', '1.0.0.1', '2606:4700:4700::1111', '2606:4700:4700::1001'),
                'cloudflare-dns.com', 'https://one.one.one.one/'),
    DnsProvider('google', 'Google', 'Run by Google.',
                ('8.8.8.8', '8.8.4.4', '2001:4860:4860::8888', '2001:4860:4860::8844'),
                'dns.google', 'https://developers.google.com/speed/public-dns'),
)}

# Simple protection: what the user wants blocked, and the service that does it:
# (choice, description, what the active service blocks).
PROTECTIVE = {
    'quad9': ('Dangerous websites', 'Blocks websites with viruses and scams.', 'dangerous websites'),
    'adguard': ('Dangerous websites and ads', 'Also blocks ads and tracking.', 'dangerous websites and ads'),
    'adguard-family': ('Family protection', 'Also blocks adult websites and shows only safe search results.',
                       'dangerous and adult websites and ads'),
}
DEFAULT_PROTECTIVE = 'quad9'
# Advanced protection: lookups LibreWard allows go here, without further blocking.
NEUTRAL = ('quad9-unfiltered', 'cloudflare', 'google')
DEFAULT_NEUTRAL = 'quad9-unfiltered'
# The network's own DNS servers; only where NetworkManager's dnsmasq forwards.
NETWORK = 'network'
# Earlier protective choices that are no longer offered.
FORMER_PROTECTIVE = {'cloudflare-security': 'quad9', 'cloudflare-family': 'adguard-family'}


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
if not set(PROTECTIVE) | set(NEUTRAL) <= set(PROVIDERS):
    raise ValueError('Every offered DNS service needs a provider entry.')
