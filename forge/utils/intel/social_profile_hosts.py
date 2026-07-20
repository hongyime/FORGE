"""Pure host guards for Epieos/social profile parsing."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from urllib.parse import urlparse

_EXTRA_SUPPORTED_PROFILE_HOSTS = (
    "adplist.org",
    "codesandbox.io",
    "contra.com",
    "speakerdeck.com",
    "stackexchange.com",
    "stackoverflow.com",
)

_STACK_EXCHANGE_NETWORK_HOSTS = {
    "askubuntu.com",
    "mathoverflow.net",
    "serverfault.com",
    "stackapps.com",
    "superuser.com",
}

_MASTODON_LIKE_HOSTS = {
    "chaos.social",
    "fosstodon.org",
    "hachyderm.io",
    "indieweb.social",
    "infosec.exchange",
    "kolektiva.social",
    "mas.to",
    "mastodonapp.uk",
    "mastodon.cloud",
    "mastodon.online",
    "mastodon.social",
    "mastodon.world",
    "masto.ai",
    "me.dm",
    "mstdn.ca",
    "mstdn.party",
    "mstdn.social",
    "sfba.social",
    "social.coop",
    "techhub.social",
    "toot.community",
    "universeodon.com",
}


def normalize_profile_hostname(value: object) -> str:
    host = str(value or "").strip().lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def profile_url_hostname(value: str) -> str:
    text = str(value or "").strip()
    parsed = urlparse(text)
    hostname = parsed.hostname
    if not hostname and text and "://" not in text and not text.startswith("//"):
        hostname = urlparse(f"//{text.lstrip('/')}").hostname
    return normalize_profile_hostname(hostname)


def epieos_host_matches(hostname: str, expected_host: str) -> bool:
    host = normalize_profile_hostname(hostname)
    expected = normalize_profile_hostname(expected_host)
    return bool(host and expected and (host == expected or host.endswith(f".{expected}")))


def epieos_is_stack_exchange_profile_host(hostname: str) -> bool:
    host = normalize_profile_hostname(hostname)
    return (
        host in _STACK_EXCHANGE_NETWORK_HOSTS
        or host == "stackoverflow.com"
        or host.endswith(".stackoverflow.com")
        or host == "stackexchange.com"
        or host.endswith(".stackexchange.com")
    )


def epieos_is_mastodon_like_host(hostname: str) -> bool:
    host = normalize_profile_hostname(hostname)
    if not host:
        return False
    return (
        host in _MASTODON_LIKE_HOSTS
        or host.startswith("mastodon.")
        or host.startswith("mstdn.")
    )


def _iter_supported_hosts(
    platform_hosts: Mapping[str, Sequence[str]],
) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for hosts in platform_hosts.values():
        for host in hosts:
            normalized = normalize_profile_hostname(host)
            if normalized and normalized not in seen:
                seen.add(normalized)
                values.append(normalized)
    for host in _EXTRA_SUPPORTED_PROFILE_HOSTS:
        normalized = normalize_profile_hostname(host)
        if normalized and normalized not in seen:
            seen.add(normalized)
            values.append(normalized)
    return values


def epieos_is_supported_profile_host(
    hostname: str,
    platform_hosts: Mapping[str, Sequence[str]],
) -> bool:
    host = normalize_profile_hostname(hostname)
    if not host:
        return False
    if any(epieos_host_matches(host, supported) for supported in _iter_supported_hosts(platform_hosts)):
        return True
    if host == "t.me" or host.endswith(".t.me"):
        return True
    if epieos_is_stack_exchange_profile_host(host):
        return True
    return epieos_is_mastodon_like_host(host)


def epieos_is_federated_instance_candidate_host(
    hostname: str,
    platform_hosts: Mapping[str, Sequence[str]],
) -> bool:
    host = normalize_profile_hostname(hostname)
    if not host or "." not in host:
        return False
    return not (
        epieos_is_supported_profile_host(host, platform_hosts)
        and not epieos_is_mastodon_like_host(host)
    )


def epieos_profile_alias_host_matches(
    platform_name: str,
    url: str,
    platform_hosts: Mapping[str, Sequence[str]],
) -> bool:
    hostname = profile_url_hostname(url)
    if not hostname:
        return False
    if platform_name in {"stackoverflow", "stack_overflow", "stackexchange", "stack_exchange"}:
        return epieos_is_stack_exchange_profile_host(hostname)
    expected_hosts = platform_hosts.get(platform_name, ())
    if expected_hosts:
        return any(epieos_host_matches(hostname, expected) for expected in expected_hosts)
    return epieos_is_supported_profile_host(hostname, platform_hosts)
