from datetime import date, datetime, timezone

import pytest
from conftest import (
    CENSYS_URL,
    CERT_SHA256,
    CERT_SUBJECT,
    INTERNETDB_URL,
    JARM,
    SCOUT_URL,
    SILENTPUSH_URL,
    URLSCAN_URL,
    censys_answer,
    censys_host,
)
from connectors_sdk.connectors.internal_hunt import (
    HuntExecutionError,
    RunDeadline,
)
from infrastructure_tracker.sources import (
    CensysClient,
    Host,
    InternetDbClient,
    ScoutClient,
    SilentPushClient,
    UrlscanClient,
    new_host,
)

START = date(2026, 10, 3)
END = date(2026, 10, 4)


@pytest.fixture
def deadline() -> RunDeadline:
    return RunDeadline(30)


def test_host_collects_unique_values():
    host = Host(key="8.8.8.8", ip="8.8.8.8", sources=["censys"])
    host.add_domain("Evil.Example.")
    host.add_domain("evil.example")
    host.add_domain(None)
    host.add_port(443)
    host.add_port("8443")
    host.add_port("https")
    host.add_port(True)
    host.add_certificate(CERT_SHA256.upper(), CERT_SUBJECT)
    host.add_certificate(CERT_SHA256)
    host.add_certificate("not-a-hash")
    host.add_certificate("z" * 64)
    host.add_fingerprint("jarm", JARM)
    host.add_fingerprint("jarm", "")
    host.add_fingerprint("jarm", {"nested": 1})
    host.add_tag({"name": "cobalt-strike"})
    host.add_tag("c2")
    host.add_tag({"id": 1})
    host.seen("2026-10-03T08:00:00Z")
    host.seen("2026-10-02T08:00:00Z")
    host.seen("garbage")

    assert host.fields() == {
        "source": ["censys"],
        "ip": "8.8.8.8",
        "domain": ["evil.example"],
        "port": [443, 8443],
        "certificate.sha256": [CERT_SHA256],
        "certificate.subject": [CERT_SUBJECT],
        "certificates": [
            {"sha256": CERT_SHA256, "subject": CERT_SUBJECT, "issuer": None}
        ],
        "jarm": [JARM],
        "tag": ["cobalt-strike", "c2"],
    }
    assert host.last_seen == datetime(2026, 10, 3, 8, tzinfo=timezone.utc)


def test_host_merge():
    first = Host(key="8.8.8.8", ip="8.8.8.8", sources=["censys"], asn=15169)
    second = Host(
        key="8.8.8.8",
        ip="8.8.8.8",
        sources=["urlscan", "censys"],
        asn=1,
        as_name="GOOGLE",
        urls=["https://8.8.8.8/"],
    )
    second.add_domain("dns.google")
    second.add_port(53)
    second.add_certificate(CERT_SHA256, issuer="CN=CA")
    second.add_fingerprint("http.title", "Google")
    second.add_tag("dns")
    second.seen("2026-10-03T08:00:00Z")
    first.merge(second)
    first.merge(Host(key="8.8.8.8"))

    assert first.sources == ["censys", "urlscan"]
    assert first.asn == 15169 and first.as_name == "GOOGLE"
    assert first.domains == ["dns.google"] and first.ports == [53]
    assert first.certificates[0].issuer == "CN=CA"
    assert first.fingerprints == {"http.title": ["Google"]}
    assert first.urls == ["https://8.8.8.8/"] and first.tags == ["dns"]
    assert first.last_seen is not None


def test_new_host_keys():
    assert new_host("x") is None
    assert new_host("x", None, "Host.Example.").key == "host.example"
    host = new_host("x", "1.2.3.4", "host.example")
    assert host.key == "1.2.3.4" and host.domains == ["host.example"]


def test_censys_search_paginates_and_maps_hosts(requests_mock, deadline):
    # Given two pages of Censys hits, a web property and an unusable hit
    web_property = {
        "web_property_v1": {
            "resource": {
                "hostname": "c2.evil.example",
                "port": 8443,
                "endpoints": [{"http": {"html_title": "Login"}}],
            }
        }
    }
    web_property_ip = {
        "web_property_v1": {"resource": {"hostname": "9.9.9.9", "port": 80}}
    }
    requests_mock.post(
        CENSYS_URL,
        [
            {
                "json": censys_answer(
                    [censys_host("8.8.8.8", ["evil.example"]), web_property],
                    "page-2",
                    total=5,
                )
            },
            {
                "json": censys_answer(
                    [web_property_ip, {"host_v1": {"resource": {}}}, {}], total=5
                )
            },
        ],
    )
    client = CensysClient("https://api.platform.censys.io", "token", "org-1")

    # When searching
    result = client.search('host.services.jarm.fingerprint = "x"', 10, deadline)

    # Then both pages are read with the organization and bearer token
    first, second = requests_mock.request_history
    assert first.headers["Authorization"] == "Bearer token"
    assert first.qs == {"organization_id": ["org-1"]}
    assert first.json() == {
        "query": 'host.services.jarm.fingerprint = "x"',
        "page_size": 10,
    }
    assert second.json()["page_token"] == "page-2"
    assert second.json()["page_size"] == 8
    assert result.total == 5
    assert result.read == 5
    host, web, web_ip = result.hosts
    assert host.key == "8.8.8.8" and host.asn == 20473 and host.as_name == "AS-CHOOPA"
    assert host.domains == ["evil.example"] and host.ports == [443]
    assert host.certificates[0].subject == CERT_SUBJECT
    assert set(host.fingerprints) == {
        "ja4x",
        "jarm",
        "ja4s",
        "banner_sha256",
        "http.title",
        "http.body_sha256",
    }
    assert host.last_seen == datetime(2026, 10, 3, 8, tzinfo=timezone.utc)
    assert web.key == "c2.evil.example" and web.ip is None and web.ports == [8443]
    assert web.fingerprints == {"http.title": ["Login"]}
    assert web_ip.ip == "9.9.9.9"


def test_censys_search_stops_at_the_limit(requests_mock, deadline):
    requests_mock.post(
        CENSYS_URL,
        json=censys_answer(
            [censys_host("8.8.8.8"), censys_host("1.1.1.1")], "next", total=9
        ),
    )
    client = CensysClient("https://api.platform.censys.io", "token", None)

    result = client.search("q", 1, deadline)

    assert requests_mock.call_count == 1
    assert requests_mock.last_request.qs == {}
    assert [host.key for host in result.hosts] == ["8.8.8.8"]
    assert result.read == 1


def test_censys_search_limits_the_hits_read_not_the_hosts_kept(requests_mock, deadline):
    # Given a first page holding a hit that maps to no host
    requests_mock.post(
        CENSYS_URL,
        [
            {"json": censys_answer([{}, censys_host("8.8.8.8")], "next", total=9)},
            {"json": censys_answer([censys_host("1.1.1.1")], "last", total=9)},
        ],
    )
    client = CensysClient("https://api.platform.censys.io", "token", None)

    # When searching with a limit of two hits
    result = client.search("q", 2, deadline)

    # Then the unusable hit counts against the limit
    assert requests_mock.call_count == 1
    assert [host.key for host in result.hosts] == ["8.8.8.8"]
    assert result.read == 2


def test_censys_search_rejects_unexpected_answers(requests_mock, deadline):
    requests_mock.post(CENSYS_URL, json=[1])
    client = CensysClient("https://api.platform.censys.io", "token", None)
    with pytest.raises(HuntExecutionError, match="unexpected answer"):
        client.search("q", 5, deadline)


def test_censys_search_reports_api_errors(requests_mock, deadline):
    requests_mock.post(CENSYS_URL, status_code=401, json={"error": "bad token"})
    client = CensysClient("https://api.platform.censys.io", "token", None)
    with pytest.raises(HuntExecutionError, match="Censys search"):
        client.search("q", 5, deadline)


def test_silentpush_search_pages_with_skip(requests_mock, deadline):
    scan = {
        "ip": "8.8.8.8",
        "hostname": "c2.evil.example",
        "domain": "evil.example",
        "port": 443,
        "jarm": JARM,
        "ssl": {"SHA256": CERT_SHA256, "subject": {"common_name": "evil.example"}},
        "htmltitle": "Login",
        "html_body_sha256": "c" * 64,
        "header": {"server": "nginx"},
        "url": "https://c2.evil.example/",
        "scan_date": "2026-10-03T08:00:00Z",
    }
    requests_mock.post(
        SILENTPUSH_URL,
        [
            {"json": {"response": {"scandata_raw": [scan] * 1000}}},
            {"json": {"response": {"scandata_raw": [{"port": 1}, {"ip": "1.1.1.1"}]}}},
        ],
    )
    client = SilentPushClient("https://api.silentpush.com", "key")

    result = client.search('jarm = "x"', 1500, deadline)

    first, second = requests_mock.request_history
    assert first.headers["X-API-Key"] == "key"
    assert first.qs == {"limit": ["1000"], "skip": ["0"]}
    assert first.json() == {"query": 'jarm = "x"'}
    assert second.qs == {"limit": ["500"], "skip": ["1000"]}
    assert len(result.hosts) == 1001 and result.total is None
    assert result.read == 1002
    # The second page came back short: every match was read
    assert result.more is False
    host = result.hosts[0]
    assert host.domains == ["c2.evil.example", "evil.example"]
    assert host.certificates[0].subject == "CN=evil.example"
    assert host.fingerprints["http.server"] == ["nginx"]
    assert host.urls == ["https://c2.evil.example/"]


def test_silentpush_search_stops_at_the_limit(requests_mock, deadline):
    requests_mock.post(
        SILENTPUSH_URL,
        json={"response": {"scandata_raw": [{"ip": "8.8.8.8", "ssl": {}}] * 3}},
    )
    client = SilentPushClient("https://api.silentpush.com", "key")

    result = client.search("q", 2, deadline)

    assert requests_mock.call_count == 1
    assert len(result.hosts) == 2
    assert result.hosts[0].certificates == []
    # The read stopped at the limit: more matches may exist
    assert result.more is True


def test_silentpush_search_reading_exactly_the_limit_may_have_more(
    requests_mock, deadline
):
    requests_mock.post(
        SILENTPUSH_URL,
        json={"response": {"scandata_raw": [{"ip": "8.8.8.8"}] * 2}},
    )
    client = SilentPushClient("https://api.silentpush.com", "key")

    result = client.search("q", 2, deadline)

    assert requests_mock.call_count == 1
    assert (result.read, result.more) == (2, True)


def test_urlscan_search_dates_the_query_and_follows_search_after(
    requests_mock, deadline
):
    item = {
        "page": {
            "domain": "evil.example",
            "ip": "8.8.8.8",
            "asn": "AS15169",
            "asnname": "GOOGLE",
            "url": "https://evil.example/login",
            "title": "Login",
            "server": "nginx",
            "tlsIssuer": "R3",
        },
        "task": {"time": "2026-10-03T08:00:00.000Z"},
        "sort": [1759478400000, "abc"],
    }
    requests_mock.get(
        URLSCAN_URL,
        [
            {"json": {"results": [item], "total": 3, "has_more": True}},
            {"json": {"results": [{"page": {}}, item], "total": 3, "has_more": False}},
        ],
    )
    client = UrlscanClient("https://urlscan.io", "key")

    result = client.search('page.title:"Login"', START, END, 10, deadline)

    first, second = requests_mock.request_history
    assert first.headers["API-Key"] == "key"
    assert first.qs["q"] == ['(page.title:"login") and date:[2026-10-03 to 2026-10-04]']
    assert first.qs["size"] == ["10"]
    assert second.qs["search_after"] == ["1759478400000,abc"]
    assert second.qs["size"] == ["9"]
    # The day-bounded total is not a hit count of the run window; every match was read
    assert (result.total, result.more) == (None, False)
    assert len(result.hosts) == 2 and result.read == 3
    host = result.hosts[0]
    assert host.asn == 15169 and host.as_name == "GOOGLE"
    assert host.fingerprints == {
        "http.title": ["Login"],
        "http.server": ["nginx"],
        "tls.issuer": ["R3"],
    }


def test_urlscan_search_stops_without_sort_values(requests_mock, deadline):
    requests_mock.get(
        URLSCAN_URL,
        json={"results": [{"page": {"ip": "8.8.8.8"}}], "has_more": True},
    )
    client = UrlscanClient("https://urlscan.io", "key")

    result = client.search("q", START, END, 10, deadline)

    assert requests_mock.call_count == 1
    assert result.total is None and len(result.hosts) == 1
    # urlscan.io said more matches exist: the missing cursor does not make the result complete
    assert result.more is True


def test_urlscan_search_flags_a_total_beyond_the_scans_read(requests_mock, deadline):
    requests_mock.get(
        URLSCAN_URL,
        json={"results": [{"page": {"ip": "8.8.8.8"}}], "total": 40, "has_more": False},
    )
    client = UrlscanClient("https://urlscan.io", "key")

    result = client.search("q", START, END, 10, deadline)

    # The total stays out of the hit count but tells that matches were left unread
    assert (result.total, result.read, result.more) == (None, 1, True)


def test_scout_search_maps_ips(requests_mock, deadline):
    requests_mock.get(
        SCOUT_URL,
        json={
            "ips": [
                {
                    "ip": "8.8.8.8",
                    "tags": [{"name": "cobalt-strike"}],
                    "summary": {
                        "whois": {"asn": 15169, "as_name": "GOOGLE"},
                        "pdns": {"pdns": [{"domain": "evil.example"}]},
                        "open_ports": {"top_open_ports": [{"port": 443}]},
                        "last_seen": "2026-10-03",
                    },
                },
                {
                    "ip": "1.1.1.1",
                    "summary": {
                        "pdns": [{"domain": "one.example"}],
                        "open_ports": [{"port": 53}],
                    },
                },
                {"summary": {}},
            ]
        },
    )
    client = ScoutClient("https://scout.cymru.com/api/scout", "key")

    result = client.search(JARM, START, END, 10000, deadline)

    request = requests_mock.last_request
    assert request.headers["Authorization"] == "Token key"
    assert request.qs == {
        "query": [JARM],
        "start_date": ["2026-10-03"],
        "end_date": ["2026-10-04"],
        "size": ["5000"],
    }
    first, second = result.hosts
    assert result.read == 3
    assert first.asn == 15169 and first.domains == ["evil.example"]
    assert first.ports == [443] and first.tags == ["cobalt-strike"]
    assert first.last_seen == datetime(2026, 10, 3, tzinfo=timezone.utc)
    assert second.domains == ["one.example"] and second.ports == [53]
    # Three IP addresses for a page of 5000: every match was read
    assert result.more is False


def test_scout_search_filling_the_page_may_have_more(requests_mock, deadline):
    requests_mock.get(
        SCOUT_URL,
        json={"ips": [{"ip": "8.8.8.8"}, {"ip": "1.1.1.1"}, {"ip": "9.9.9.9"}]},
    )
    client = ScoutClient("https://scout.cymru.com/api/scout", "key")

    result = client.search(JARM, START, END, 2, deadline)

    assert requests_mock.last_request.qs["size"] == ["2"]
    assert (result.read, result.more) == (2, True)


def test_internetdb_lookup_enriches_hosts(requests_mock, deadline):
    requests_mock.get(
        f"{INTERNETDB_URL}/8.8.8.8",
        json={"hostnames": ["dns.google"], "ports": [53, 443], "tags": ["cdn"]},
    )
    host = Host(key="8.8.8.8", ip="8.8.8.8")

    assert InternetDbClient(base_url=INTERNETDB_URL).lookup(host, deadline) is True
    assert host.domains == ["dns.google"] and host.ports == [53, 443]
    assert host.tags == ["cdn"]


def test_internetdb_lookup_unknown_ip(requests_mock, deadline):
    requests_mock.get(
        f"{INTERNETDB_URL}/8.8.8.8", status_code=404, json={"detail": "No information"}
    )
    host = Host(key="8.8.8.8", ip="8.8.8.8")

    assert InternetDbClient(base_url=INTERNETDB_URL).lookup(host, deadline) is False
    assert host.domains == []


def test_internetdb_lookup_reports_errors(requests_mock, deadline):
    requests_mock.get(f"{INTERNETDB_URL}/8.8.8.8", status_code=403, text="denied")
    host = Host(key="8.8.8.8", ip="8.8.8.8")

    with pytest.raises(HuntExecutionError, match="InternetDB"):
        InternetDbClient(base_url=INTERNETDB_URL).lookup(host, deadline)
