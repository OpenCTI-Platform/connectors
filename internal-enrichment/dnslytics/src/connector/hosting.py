import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import dns.exception
import dns.resolver
from dnslytics_client import AsInfo, DnslyticsApiError, DnslyticsClient

DNS_LIFETIME_SECONDS = 5.0
DNS_WORKERS = 16
IP2ASN_WORKERS = 4


def resolve_domain(
    domain: str, resolver: dns.resolver.Resolver | None = None
) -> list[str]:
    """Return the A and AAAA records of `domain`, or an empty list if it does not resolve."""
    resolver = resolver or dns.resolver.Resolver()
    resolver.lifetime = DNS_LIFETIME_SECONDS
    ips: list[str] = []
    for record_type in ("A", "AAAA"):
        try:
            answer = resolver.resolve(domain, record_type)
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
        ):
            continue
        except dns.exception.DNSException:
            # Timeouts and other transient errors: treat as not resolving
            continue
        ips.extend(record.to_text() for record in answer)
    return ips


@dataclass
class Hosting:
    """Where the active domains of one run are hosted."""

    ips_by_domain: dict[str, list[str]] = field(default_factory=dict)
    as_by_ip: dict[str, AsInfo] = field(default_factory=dict)
    ip2asn_calls: int = 0
    ip2asn_errors: dict[str, str] = field(default_factory=dict)


def derive_hosting(
    domains: list[str],
    client: DnslyticsClient,
    resolve=None,
) -> Hosting:
    """
    domain -> IP (DNS, free) -> AS (IP2ASN, free).
    IPs are de-duplicated before the AS lookup, so each IP costs one IP2ASN call.
    """
    resolve = resolve or resolve_domain
    hosting = Hosting()
    with ThreadPoolExecutor(max_workers=DNS_WORKERS) as pool:
        for domain, ips in zip(domains, pool.map(resolve, domains)):
            # dict.fromkeys keeps order and drops duplicates
            hosting.ips_by_domain[domain] = list(dict.fromkeys(ips))

    unique_ips = list(
        dict.fromkeys(ip for ips in hosting.ips_by_domain.values() for ip in ips)
    )
    # One failed IP must not lose the whole run: record it and go on, unless
    # DNSlytics refuses access (403) or the daily cap is hit, then stop calling.
    stop = threading.Event()

    def lookup(ip: str) -> AsInfo | DnslyticsApiError | None:
        if stop.is_set():
            return DnslyticsApiError("skipped after an earlier refusal")
        try:
            return client.ip2asn(ip)
        except DnslyticsApiError as err:
            if err.status_code in (403, None):
                stop.set()
            return err

    with ThreadPoolExecutor(max_workers=IP2ASN_WORKERS) as pool:
        for ip, result in zip(unique_ips, pool.map(lookup, unique_ips)):
            if isinstance(result, DnslyticsApiError):
                hosting.ip2asn_errors[ip] = str(result)
            else:
                hosting.ip2asn_calls += 1
                if result is not None:
                    hosting.as_by_ip[ip] = result
    return hosting
