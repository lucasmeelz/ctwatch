"""Derives the outbound host allowlist from the configuration.

The list is built only from services the operator has declared. A watched
domain never ends up here, which is what makes the passive-only guarantee
mechanical rather than aspirational.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ctwatch.config import Config
from ctwatch.net.client import HostAllowlist

# Fixed hosts for services that have no configurable endpoint.
STATIC_HOSTS: tuple[str, ...] = ("urlscan.io",)


def _host_of(url: str) -> str | None:
    host = urlsplit(url).hostname
    return host.lower() if host else None


def allowed_hosts(config: Config) -> list[str]:
    """Return every host ctwatch is permitted to contact, as a sorted list."""

    hosts: set[str] = set(STATIC_HOSTS)

    for url in (
        config.sources.crtsh.base_url,
        config.sources.certspotter.base_url,
        config.sources.certstream.url,
        config.enrich.dns.resolver_url,
        config.enrich.rdap.bootstrap_url,
    ):
        host = _host_of(url)
        if host:
            hosts.add(host)

    if config.notify.webhook.enabled:
        # Opting into a webhook is declaring its host, the same way a source is
        # declared. It is never inferred from anything observed.
        host = _host_of(config.notify.webhook.url)
        if host:
            hosts.add(host)

    hosts.update(config.network.extra_allowed_hosts)
    return sorted(hosts)


def build_allowlist(config: Config) -> HostAllowlist:
    """The declared hosts.

    RDAP registry servers are not here: they are learned at run time from
    IANA's bootstrap document and added with that origin recorded, because no
    configuration file can enumerate several hundred registries.
    """

    return HostAllowlist(allowed_hosts(config), origin="configuration")
