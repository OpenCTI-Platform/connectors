from unittest.mock import MagicMock

import dns.exception
import dns.resolver
from conftest import FakeResponse, FakeSession, default_routes, fake_resolve
from connector.hosting import derive_hosting, resolve_domain
from dnslytics_client import DnslyticsClient


def make_client(routes) -> DnslyticsClient:
    return DnslyticsClient(
        MagicMock(),
        api_base_url="https://api.dnslytics.net",
        api_key="k",
        session=FakeSession(routes),
        sleep=lambda _: None,
    )


def test_hosting_maps_each_unique_ip_once():
    client = make_client(default_routes())

    hosting = derive_hosting(
        ["armeniadaily.am", "armenianews.example", "armenia-daily.example"],
        client,
        resolve=fake_resolve,
    )

    assert hosting.ips_by_domain["armenia-daily.example"] == []
    assert hosting.as_by_ip["45.84.204.99"].name == "Hostinger International Limited"
    assert hosting.ip2asn_calls == 2
    assert len(client.session.calls) == 2


def test_forbidden_ip2asn_stops_further_lookups():
    forbidden = FakeResponse(
        403, {"status": "error", "data": "Forbidden access denied!"}
    )
    ips = {f"d{i}.example": [f"198.51.100.{i}"] for i in range(20)}
    client = make_client({f"/v1/ip2asn/{ip[0]}": forbidden for ip in ips.values()})

    hosting = derive_hosting(list(ips), client, resolve=lambda d: ips[d])

    assert hosting.as_by_ip == {}
    assert len(hosting.ip2asn_errors) == 20
    # At most one call per worker before the stop flag is seen
    assert len(client.session.calls) <= 4


class FakeResolver:
    def __init__(self, answers):
        self.answers = answers
        self.lifetime = None

    def resolve(self, domain, record_type):
        answer = self.answers.get((domain, record_type))
        if isinstance(answer, Exception):
            raise answer
        if answer is None:
            raise dns.resolver.NoAnswer()
        return [MagicMock(to_text=lambda value=value: value) for value in answer]


def test_resolve_domain_returns_a_and_aaaa():
    resolver = FakeResolver(
        {
            ("x.example", "A"): ["192.0.2.1"],
            ("x.example", "AAAA"): ["2001:db8::1"],
        }
    )

    assert resolve_domain("x.example", resolver) == ["192.0.2.1", "2001:db8::1"]
    assert resolver.lifetime == 5.0


def test_resolve_domain_treats_nxdomain_and_timeouts_as_not_resolving():
    resolver = FakeResolver(
        {
            ("x.example", "A"): dns.resolver.NXDOMAIN(),
            ("x.example", "AAAA"): dns.exception.Timeout(),
        }
    )

    assert resolve_domain("x.example", resolver) == []
